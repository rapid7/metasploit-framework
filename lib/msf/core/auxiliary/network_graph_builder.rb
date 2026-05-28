# frozen_string_literal: true

module Msf
  module Auxiliary
    module NetworkGraphBuilder
      MSF_NODE_ID = '__msf__'

      def load_workspace_data(ws)
        hosts         = ws.hosts.includes(:services, :sessions).all.to_a
        db_sessions   = ws.sessions.all.to_a
        traceroutes   = ws.notes.where(ntype: 'host.nmap.traceroute').includes(:host).to_a
        host_loots    = ws.loots.where.not(host_id: nil).to_a
        host_vulns    = ws.vulns.includes(:refs).all.to_a
        all_cve_names = host_vulns.flat_map { |v|
          v.refs.map(&:name).select { |r| r.upcase.start_with?('CVE-') }.map(&:upcase)
        }.uniq
        cve_module_map = build_cve_module_map(all_cve_names)

        snmp_notes = ws.notes.where(ntype: %w[
          snmp.Hostname snmp.Description snmp.Contact snmp.Location
          snmp.Network\ interfaces snmp.LLDP\ Neighbors snmp.CDP\ Neighbors
          snmp.MAC\ Address\ Table
        ]).includes(:host).to_a
        snmp_by_host = snmp_notes.each_with_object(Hash.new { |h, k| h[k] = {} }) do |n, m|
          next unless n.host_id

          key     = n.ntype.sub('snmp.', '')
          content = n.data.is_a?(Hash) ? (n.data['content'] || n.data[:content]) : nil
          m[n.host_id][key] = content.to_s if content
        end

        module_run_events = ws.events.where(name: 'module_run').all.to_a
        host_ids          = hosts.map(&:id)

        direct_module_runs = begin
          MetasploitDataModels::ModuleRun
            .where(trackable_type: 'Mdm::Host', trackable_id: host_ids)
            .all.to_a
        rescue StandardError
          []
        end

        host_cred_logins = begin
          Metasploit::Credential::Login
            .in_workspace_including_hosts_and_services(ws)
            .includes(core: [:realm])
            .all.to_a
        rescue StandardError => e
          print_warning("Credential login query failed: #{e.class}: #{e.message}")
          []
        end

        {
          hosts: hosts, db_sessions: db_sessions, traceroute_notes: traceroutes,
          host_loots: host_loots, host_vulns: host_vulns, cve_module_map: cve_module_map,
          snmp_by_host: snmp_by_host, module_run_events: module_run_events,
          direct_module_runs: direct_module_runs, host_cred_logins: host_cred_logins
        }
      end

      def build_graph_data(ws_data, session_limit: 0, loot_limit: 0, cred_limit: 0)
        hosts              = ws_data[:hosts]
        db_sessions        = ws_data[:db_sessions]
        traceroute_notes   = ws_data[:traceroute_notes]
        host_loots         = ws_data[:host_loots]
        host_vulns         = ws_data[:host_vulns]
        cve_module_map     = ws_data[:cve_module_map] || {}
        snmp_by_host       = ws_data[:snmp_by_host] || {}
        module_run_events  = ws_data[:module_run_events]
        direct_module_runs = ws_data[:direct_module_runs]
        cred_by_host       = (ws_data[:host_cred_logins] || []).group_by { |l| l.service.host_id }

        nodes      = []
        links_set  = Set.new

        lhost = begin
          Rex::Socket.source_address
        rescue StandardError
          '127.0.0.1'
        end
        local_hostname = begin
          Socket.gethostname
        rescue StandardError
          'localhost'
        end

        nodes << {
          id: MSF_NODE_ID, label: 'Metasploit', address: lhost, name: local_hostname,
          mac: '', os_name: 'Metasploit Framework', os_flavor: '', os_sp: '', os_family: 'msf',
          purpose: 'msf', arch: '', compromised: false, ever_compromised: false,
          session_count: 0, sessions: [], services: [], loots: [], device_type: 'msf'
        }

        session_by_host    = db_sessions.group_by(&:host_id)
        loot_by_host       = host_loots.group_by(&:host_id)
        vuln_by_host       = host_vulns.group_by(&:host_id)
        module_run_by_host = direct_module_runs.group_by(&:trackable_id)

        ipv4_re = /\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/
        event_modules_by_ip = Hash.new { |h, k| h[k] = Set.new }
        module_run_events.each do |ev|
          info = ev.info
          next unless info.is_a?(Hash)

          mod  = info[:module_name] || info['module_name']
          next unless mod

          ds    = info[:datastore] || info['datastore'] || {}
          rhost = ds['RHOST'] || ds['RHOSTS']
          next unless rhost.to_s =~ ipv4_re

          event_modules_by_ip[rhost.to_s].add(mod)
        end

        subnet_to_pivot = {}
        db_sessions.each do |db_session|
          next unless db_session.respond_to?(:routes)

          db_session.routes.each do |route|
            subnet_to_pivot["#{route.subnet}/#{route.netmask}"] = db_session.host_id
          end
        end

        host_id_by_addr = hosts.each_with_object({}) { |h, m| m[h.address.to_s] = "host_#{h.id}" }

        mac_to_host = hosts.each_with_object({}) do |h, m|
          next if h.mac.nil? || h.mac.empty?

          m[h.mac.downcase] = h
        end

        host_behind_switch = {}
        snmp_by_host.each do |switch_host_id, snmp_data|
          mac_table_text = snmp_data['MAC Address Table']
          next if mac_table_text.nil? || mac_table_text.empty?

          parse_snmp_table(mac_table_text).each do |entry|
            mac     = entry['MAC Address'].to_s.downcase
            next if mac.empty?

            matched = mac_to_host[mac]
            next unless matched
            next if matched.id == switch_host_id

            host_behind_switch[matched.id] ||= switch_host_id
          end
        end

        host_behind_switch_node_ids = host_behind_switch.keys.map { |id| "host_#{id}" }.to_set

        hop_nodes           = {}
        host_rtt            = {}
        hosts_with_traceroute = Set.new

        traceroute_notes.each do |note|
          next unless note.data.is_a?(Hash)

          hops = note.data['hops'] || []
          next if hops.empty?

          target_addr = note.host&.address&.to_s
          prev_id     = MSF_NODE_ID

          hops.each do |hop|
            ip = (hop['address'] || hop['ipaddr']).to_s.strip
            next if ip.empty? || ip == '*'

            rtt_val = hop['rtt'].to_f
            rtt_val = nil unless rtt_val > 0

            current_id = if host_id_by_addr.key?(ip)
                           nid = host_id_by_addr[ip]
                           host_rtt[nid] ||= rtt_val
                           nid
                         elsif hop_nodes.key?(ip)
                           hop_nodes[ip][:rtt] ||= rtt_val
                           hop_nodes[ip][:id]
                         else
                           node_id = "hop_#{ip.gsub(/[^0-9a-f:]/i, '_')}"
                           hop_nodes[ip] = {
                             id: node_id,
                             label: hop['name'].to_s.empty? ? ip : hop['name'],
                             address: ip, name: hop['name'] || '',
                             mac: '', os_name: '', os_flavor: '', os_sp: '', os_family: '',
                             purpose: '', arch: '', compromised: false, ever_compromised: false,
                             session_count: 0, sessions: [], services: [], loots: [],
                             device_type: 'router', rtt: rtt_val
                           }
                           node_id
                         end

            links_set.add([prev_id, current_id])
            prev_id = current_id
          end

          hosts_with_traceroute.add(target_addr) if target_addr

          if target_addr && host_id_by_addr.key?(target_addr)
            target_id = host_id_by_addr[target_addr]
            links_set.add([prev_id, target_id]) unless prev_id == target_id || host_behind_switch_node_ids.include?(target_id)
          end
        end

        hosts.each do |host|
          host_sessions   = session_by_host[host.id] || []
          active_sessions = host_sessions.select { |s| s.closed_at.nil? }

          display_sessions = session_limit > 0 ? host_sessions.sort_by { |s| s.opened_at || Time.at(0) }.last(session_limit) : host_sessions
          session_data = display_sessions.map do |s|
            ds = s.datastore.is_a?(Hash) ? s.datastore : {}
            {
              id: s.id, type: s.stype || 'unknown',
              via_exploit: s.via_exploit || '', via_payload: s.via_payload || '',
              lhost: ds['LHOST'] || '', lport: ds['LPORT'] || '', rport: ds['RPORT'] || '',
              opened_at: s.opened_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
              closed_at: s.closed_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
              active: s.closed_at.nil?
            }
          end

          service_data = host.services
                             .sort_by(&:port)
                             .map { |svc| { port: svc.port, proto: svc.proto, name: svc.name || '', state: svc.state || '' } }

          display_loots = loot_by_host[host.id] || []
          display_loots = display_loots.last(loot_limit) if loot_limit > 0
          loot_data = display_loots.map { |l| { ltype: l.ltype || '', name: l.name || '', info: l.info || '', path: l.path || '' } }

          vuln_data = (vuln_by_host[host.id] || []).filter_map do |v|
            cve_refs = v.refs.map(&:name).select { |r| r.upcase.start_with?('CVE-') }.map(&:upcase)
            next if cve_refs.empty?

            modules_for_vuln = cve_refs.flat_map { |cve| cve_module_map[cve] || [] }.uniq.sort
            {
              name: v.name || '', info: v.info || '',
              refs: v.refs.map(&:name), cve_refs: cve_refs,
              msf_modules: modules_for_vuln,
              exploited_at: v.exploited_at&.strftime('%Y-%m-%d %H:%M:%S') || ''
            }
          end

          host_module_runs = (module_run_by_host[host.id] || []).map do |mr|
            { module_fullname: mr.module_fullname || '', status: mr.status || '',
              attempted_at: mr.attempted_at&.strftime('%Y-%m-%d %H:%M:%S') || '' }
          end

          display_creds = (cred_by_host[host.id] || []).uniq(&:core_id)
          display_creds = display_creds.last(cred_limit) if cred_limit > 0
          cred_data = display_creds.map do |login|
            core = login.core
            {
              type: core.private&.type&.split('::')&.last || 'Unknown',
              username: core.public&.username || '',
              domain: core.realm&.value || '',
              status: login.status || ''
            }
          end

          snmp            = snmp_by_host[host.id] || {}
          snmp_hostname   = snmp['Hostname'].to_s.strip
          effective_label = if !snmp_hostname.empty? && (host.name.nil? || host.name.empty?)
                              snmp_hostname
                            else
                              host.name || host.address.to_s
                            end
          snmp_type = snmp_device_type(snmp['Description'])

          snmp_mac_table = parse_snmp_table(snmp['MAC Address Table'])
          port_host_map  = snmp_mac_table.filter_map do |entry|
            mac = entry['MAC Address'].to_s.downcase
            next if mac.empty?

            matched = mac_to_host[mac]
            {
              port: entry['Port'] || '', mac: entry['MAC Address'] || '', status: entry['Status'] || '',
              host_id: matched ? "host_#{matched.id}" : nil,
              host_ip: matched ? matched.address.to_s : '',
              host_label: matched ? (matched.name || matched.address.to_s) : ''
            }
          end

          nodes << {
            id: "host_#{host.id}", label: effective_label,
            address: host.address.to_s, name: host.name || '',
            mac: host.mac || '', os_name: host.os_name || '',
            os_flavor: host.os_flavor || '', os_sp: host.os_sp || '',
            os_family: host.os_family || '', purpose: host.purpose || '',
            arch: host.arch || '', compromised: active_sessions.any?,
            ever_compromised: host_sessions.any?, session_count: active_sessions.count,
            sessions: session_data, services: service_data, loots: loot_data,
            vulns: vuln_data, vuln_cve_count: vuln_data.length,
            vuln_module_count: vuln_data.count { |v| v[:msf_modules].any? },
            event_modules: event_modules_by_ip[host.address.to_s].to_a.sort,
            module_runs: host_module_runs, creds: cred_data,
            snmp_hostname: snmp_hostname, snmp_description: snmp['Description'] || '',
            snmp_contact: snmp['Contact'] || '', snmp_location: snmp['Location'] || '',
            snmp_interfaces: parse_snmp_table(snmp['Network interfaces']),
            snmp_lldp: parse_snmp_table(snmp['LLDP Neighbors']),
            snmp_cdp: parse_snmp_table(snmp['CDP Neighbors']),
            snmp_port_hosts: port_host_map,
            device_type: snmp_type || infer_device_type(host),
            rtt: host_rtt["host_#{host.id}"]
          }

          next if hosts_with_traceroute.include?(host.address.to_s) && !host_behind_switch.key?(host.id)

          source_id = if host_behind_switch.key?(host.id)
                        "host_#{host_behind_switch[host.id]}"
                      elsif (pivot_host_id = find_pivot_for_host(host, subnet_to_pivot))
                        "host_#{pivot_host_id}"
                      else
                        MSF_NODE_ID
                      end
          links_set.add([source_id, "host_#{host.id}"])
        end

        nodes.concat(hop_nodes.values)
        links = links_set.map { |s, t| { source: s, target: t } }
        [nodes, links]
      end

      def build_cve_module_map(cve_names)
        return {} if cve_names.empty?

        cve_set = cve_names.map(&:upcase).to_set
        map = {}
        Msf::Modules::Metadata::Cache.instance.get_metadata.each do |mod_meta|
          mod_meta.references.each do |ref|
            cve_key = ref.upcase
            next unless cve_set.include?(cve_key)

            (map[cve_key] ||= []) << mod_meta.fullname
          end
        end
        map
      rescue StandardError => e
        print_warning("CVE→module mapping failed: #{e.class}: #{e.message}")
        {}
      end

      def infer_device_type(host)
        purpose = host.purpose.to_s.downcase
        return 'router'   if purpose.match?(/router/)
        return 'switch'   if purpose.match?(/switch/)
        return 'firewall' if purpose.match?(/firewall/)
        return 'printer'  if purpose.match?(/print/)
        return 'phone'    if purpose.match?(/phone|mobile/)
        return 'server'   if purpose.match?(/server/)
        return 'computer' if purpose.match?(/client|workstation/)

        ports = host.services.map(&:port)
        return 'server' if (ports & [80, 443, 8080, 8443, 3306, 5432, 1433]).any?
        return 'router' if (ports & [179, 520, 521]).any?

        'computer'
      end

      def find_pivot_for_host(host, subnet_to_pivot)
        ip = IPAddr.new(host.address.to_s)
        subnet_to_pivot.each do |cidr, pivot_host_id|
          subnet_ip, netmask = cidr.split('/')
          net = IPAddr.new("#{subnet_ip}/#{netmask}")
          return pivot_host_id if net.include?(ip)
        rescue ArgumentError
          next
        end
        nil
      rescue ArgumentError
        nil
      end

      def snmp_device_type(description)
        return nil if description.nil? || description.empty?

        desc = description.downcase
        return 'router'   if desc.match?(/router|cisco ios|junos|ios xe|ios xr|vyos|pfsense|opnsense|routeros/)
        return 'switch'   if desc.match?(/switch|catalyst|nexus|arista eos|juniper ex|procurve/)
        return 'firewall' if desc.match?(/firewall|fortigate|asa|checkpoint|sonicwall|palo alto/)
        return 'printer'  if desc.match?(/printer|jetdirect/)

        nil
      end

      def parse_snmp_table(text)
        return [] if text.nil? || text.empty?

        text.split(/\n\n+/).filter_map do |block|
          row = block.split("\n").each_with_object({}) do |line, h|
            m = line.match(/^(.+?)\s*:\s*(.*)$/)
            next unless m

            h[m[1].strip] = m[2].strip
          end
          row.empty? ? nil : row
        end
      end

      def utf8_sanitize(obj)
        case obj
        when Hash  then obj.transform_values { |v| utf8_sanitize(v) }
        when Array then obj.map { |v| utf8_sanitize(v) }
        when String
          return obj if obj.encoding == ::Encoding::UTF_8 && obj.valid_encoding?

          obj.dup.force_encoding('UTF-8').scrub('?')
        else obj
        end
      end
    end
  end
end
