# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Network Topology/Graph Visualizer',
        'Description' => %q{
          Generates an interactive network graph visualization from hosts, sessions,
          and routes stored in the Metasploit database. The output is a self-contained
          HTML file saved via store_loot that can be opened in any modern web browser.
          Features include draggable nodes, device-type icons with click-to-override,
          OS-specific icons, compromise indicators, path highlighting back to the MSF
          node, and a details panel showing host information.
        },
        'Author' => ['h00die'],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptBool.new('EMBED_JS', [false, 'Embed D3.js inline for a fully self-contained offline HTML file', false]),
        OptInt.new('LIMIT_SESSION', [false, 'Max sessions to include per host (0 = unlimited, most recent first)', 0]),
        OptInt.new('LIMIT_LOOT', [false, 'Max loot items to include per host (0 = unlimited, most recent first)', 0]),
        OptInt.new('LIMIT_CRED', [false, 'Max credentials to include per host (0 = unlimited)', 0])
      ]
    )
  end

  def run
    fail_with(Failure::BadConfig, 'No database connected. Please connect to a database first (db_connect or db_status).') unless framework.db.active

    ws = myworkspace
    hosts = ws.hosts.includes(:services, :sessions).all.to_a
    db_sessions = ws.sessions.all.to_a
    traceroute_notes = ws.notes.where(ntype: 'host.nmap.traceroute').includes(:host).to_a
    host_loots = ws.loots.where.not(host_id: nil).to_a
    host_vulns = ws.vulns.includes(:refs).all.to_a
    module_run_events = ws.events.where(name: 'module_run').all.to_a
    host_ids = hosts.map(&:id)
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

    print_status('Building network graph:')
    print_status("  Hosts:             #{hosts.length}")
    print_status("  Sessions:          #{db_sessions.length}")
    print_status("  Traceroutes:       #{traceroute_notes.length}")
    print_status("  Loot items:        #{host_loots.length}")
    print_status("  Vulns:             #{host_vulns.length}")
    print_status("  Module events:     #{module_run_events.length}")
    print_status("  Module runs:       #{direct_module_runs.length}")
    print_status("  Credential logins: #{host_cred_logins.length}")

    ws_data = {
      hosts: hosts,
      db_sessions: db_sessions,
      traceroute_notes: traceroute_notes,
      host_loots: host_loots,
      host_vulns: host_vulns,
      module_run_events: module_run_events,
      direct_module_runs: direct_module_runs,
      host_cred_logins: host_cred_logins
    }
    nodes, links = build_graph_data(ws_data)
    html = generate_html(nodes, links)

    # nil ctype lets the filename extension (.html) win; 'text/html' would force .txt via store_loot's text/* override
    # lib/msf/core/auxiliary/report.rb line 413
    loot_path = store_loot('network.graph', nil, nil, html, 'network_graph.html', 'MSF Network Graph Visualization')
    print_good("Network graph saved to: #{loot_path}")
  end

  private

  MSF_NODE_ID = '__msf__'

  TEMPLATE_PATH = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map', 'network_map_template.html')
  D3_LOCAL_PATH = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map', 'd3.v7.9.0.min.js')
  D3_CDN_TAG = '<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js" crossorigin="anonymous"></script>'

  def build_graph_data(ws_data)
    hosts = ws_data[:hosts]
    db_sessions = ws_data[:db_sessions]
    traceroute_notes = ws_data[:traceroute_notes]
    host_loots = ws_data[:host_loots]
    host_vulns = ws_data[:host_vulns]
    module_run_events = ws_data[:module_run_events]
    direct_module_runs = ws_data[:direct_module_runs]
    cred_by_host = (ws_data[:host_cred_logins] || []).group_by { |l| l.service.host_id }

    nodes = []
    links_set = Set.new

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
      id: MSF_NODE_ID,
      label: 'Metasploit',
      address: lhost,
      name: local_hostname,
      mac: '',
      os_name: 'Metasploit Framework',
      os_flavor: '',
      os_sp: '',
      os_family: 'msf',
      purpose: 'msf',
      arch: '',
      compromised: false,
      ever_compromised: false,
      session_count: 0,
      sessions: [],
      services: [],
      loots: [],
      device_type: 'msf'
    }

    session_by_host = db_sessions.group_by(&:host_id)
    loot_by_host = host_loots.group_by(&:host_id)
    vuln_by_host = host_vulns.group_by(&:host_id)
    module_run_by_host = direct_module_runs.group_by(&:trackable_id)

    # Build ip → [module_name] map from module_run events (single-IP RHOST only)
    ipv4_re = /\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/
    event_modules_by_ip = Hash.new { |h, k| h[k] = Set.new }
    module_run_events.each do |ev|
      info = ev.info
      next unless info.is_a?(Hash)

      mod = info[:module_name] || info['module_name']
      next unless mod

      ds = info[:datastore] || info['datastore'] || {}
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

    # Build addr→node_id map for known hosts (used for traceroute link resolution)
    host_id_by_addr = hosts.each_with_object({}) { |h, m| m[h.address.to_s] = "host_#{h.id}" }

    # Parse traceroute notes to build intermediate hop nodes and directed link chains.
    # Both nmap importers write hops; nmap_document.rb uses "ipaddr", nmap.rb uses "address".
    hop_nodes = {}
    host_rtt = {} # node_id → rtt (ms) for known hosts seen in traceroute hops
    hosts_with_traceroute = Set.new

    traceroute_notes.each do |note|
      next unless note.data.is_a?(Hash)

      hops = note.data['hops'] || []
      next if hops.empty?

      target_addr = note.host&.address&.to_s
      prev_id = MSF_NODE_ID

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
                         address: ip,
                         name: hop['name'] || '',
                         mac: '', os_name: '', os_flavor: '', os_sp: '', os_family: '',
                         purpose: '', arch: '',
                         compromised: false, ever_compromised: false,
                         session_count: 0, sessions: [], services: [], loots: [],
                         device_type: 'router',
                         rtt: rtt_val
                       }
                       node_id
                     end

        links_set.add([prev_id, current_id])
        prev_id = current_id
      end

      hosts_with_traceroute.add(target_addr) if target_addr

      # Ensure last hop connects to the known target host node when they differ
      if target_addr && host_id_by_addr.key?(target_addr)
        target_id = host_id_by_addr[target_addr]
        links_set.add([prev_id, target_id]) unless prev_id == target_id
      end
    end

    if subnet_to_pivot.empty? && traceroute_notes.empty?
      print_warning('No session routes or traceroute data found. All hosts will appear as directly connected to the MSF node. For better topology, run nmap with --traceroute or add routes via "route add" after obtaining a pivot session.')
    end

    hosts.each do |host|
      host_sessions = session_by_host[host.id] || []
      active_sessions = host_sessions.select { |s| s.closed_at.nil? }

      session_limit = datastore['LIMIT_SESSION'].to_i
      display_sessions = session_limit > 0 ? host_sessions.sort_by { |s| s.opened_at || Time.at(0) }.last(session_limit) : host_sessions

      session_data = display_sessions.map do |s|
        ds = s.datastore.is_a?(Hash) ? s.datastore : {}
        {
          id: s.id,
          type: s.stype || 'unknown',
          via_exploit: s.via_exploit || '',
          via_payload: s.via_payload || '',
          lhost: ds['LHOST'] || '',
          lport: ds['LPORT'] || '',
          rport: ds['RPORT'] || '',
          opened_at: s.opened_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
          closed_at: s.closed_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
          active: s.closed_at.nil?
        }
      end

      service_data = host.services
                         .sort_by(&:port)
                         .map { |svc| { port: svc.port, proto: svc.proto, name: svc.name || '', state: svc.state || '' } }

      loot_limit = datastore['LIMIT_LOOT'].to_i
      display_loots = loot_by_host[host.id] || []
      display_loots = display_loots.last(loot_limit) if loot_limit > 0

      loot_data = display_loots.map do |l|
        {
          ltype: l.ltype || '',
          name: l.name || '',
          info: l.info || '',
          path: l.path || ''
        }
      end

      vuln_data = (vuln_by_host[host.id] || []).map do |v|
        {
          name: v.name || '',
          info: v.info || '',
          refs: v.refs.map(&:name),
          exploited_at: v.exploited_at&.strftime('%Y-%m-%d %H:%M:%S') || ''
        }
      end

      host_module_runs = (module_run_by_host[host.id] || []).map do |mr|
        {
          module_fullname: mr.module_fullname || '',
          status: mr.status || '',
          attempted_at: mr.attempted_at&.strftime('%Y-%m-%d %H:%M:%S') || ''
        }
      end

      cred_limit = datastore['LIMIT_CRED'].to_i
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

      nodes << {
        id: "host_#{host.id}",
        label: (host.name || host.address.to_s),
        address: host.address.to_s,
        name: host.name || '',
        mac: host.mac || '',
        os_name: host.os_name || '',
        os_flavor: host.os_flavor || '',
        os_sp: host.os_sp || '',
        os_family: host.os_family || '',
        purpose: host.purpose || '',
        arch: host.arch || '',
        compromised: active_sessions.any?,
        ever_compromised: host_sessions.any?,
        session_count: active_sessions.count,
        sessions: session_data,
        services: service_data,
        loots: loot_data,
        vulns: vuln_data,
        event_modules: event_modules_by_ip[host.address.to_s].to_a.sort,
        module_runs: host_module_runs,
        creds: cred_data,
        device_type: infer_device_type(host),
        rtt: host_rtt["host_#{host.id}"]
      }

      # Traceroute takes precedence; only add a default link if no traceroute covers this host
      next if hosts_with_traceroute.include?(host.address.to_s)

      pivot_host_id = find_pivot_for_host(host, subnet_to_pivot)
      source_id = pivot_host_id ? "host_#{pivot_host_id}" : MSF_NODE_ID
      links_set.add([source_id, "host_#{host.id}"])
    end

    nodes.concat(hop_nodes.values)
    links = links_set.map { |s, t| { source: s, target: t } }

    [nodes, links]
  end

  def infer_device_type(host)
    purpose = host.purpose.to_s.downcase
    return 'router' if purpose.match?(/router/)
    return 'switch' if purpose.match?(/switch/)
    return 'firewall' if purpose.match?(/firewall/)
    return 'printer' if purpose.match?(/print/)
    return 'phone' if purpose.match?(/phone|mobile/)
    return 'server' if purpose.match?(/server/)
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

  def generate_html(nodes, links)
    template = File.binread(TEMPLATE_PATH).force_encoding('UTF-8')
    d3_tag = if datastore['EMBED_JS']
               if File.exist?(D3_LOCAL_PATH)
                 "<script>#{File.read(D3_LOCAL_PATH)}</script>"
               else
                 print_warning("D3 local file not found at #{D3_LOCAL_PATH}, falling back to CDN")
                 D3_CDN_TAG
               end
             else
               D3_CDN_TAG
             end
    template
      .sub('%%D3_SCRIPT%%', d3_tag)
      .sub('%%NODES%%', JSON.generate(utf8_sanitize(nodes)).force_encoding('UTF-8'))
      .sub('%%LINKS%%', JSON.generate(utf8_sanitize(links)).force_encoding('UTF-8'))
  end

  # Recursively re-encodes all strings in a nested Hash/Array as valid UTF-8.
  # DB strings (SSH keys, binary fields) often come back tagged ASCII-8BIT;
  # force_encoding reinterprets the bytes as UTF-8, scrub drops any invalid sequences.
  def utf8_sanitize(obj)
    case obj
    when Hash then obj.transform_values { |v| utf8_sanitize(v) }
    when Array then obj.map { |v| utf8_sanitize(v) }
    when String
      return obj if obj.encoding == ::Encoding::UTF_8 && obj.valid_encoding?

      obj.dup.force_encoding('UTF-8').scrub('?')
    else obj
    end
  end
end
