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
        OptBool.new('EMBED_JS', [false, 'Embed D3.js inline for a fully self-contained offline HTML file', false])
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

    print_status("Building network graph: #{hosts.length} hosts, #{db_sessions.length} recorded sessions, #{traceroute_notes.length} traceroutes, #{host_loots.length} loot items")

    nodes, links = build_graph_data(hosts, db_sessions, traceroute_notes, host_loots)
    html = generate_html(nodes, links)

    # nil ctype lets the filename extension (.html) win; 'text/html' would force .txt via store_loot's text/* override
    # lib/msf/core/auxiliary/report.rb line 413
    loot_path = store_loot('network.graph', nil, nil, html, 'network_graph.html', 'MSF Network Graph Visualization')
    print_good("Network graph saved to: #{loot_path}")
  end

  private

  MSF_NODE_ID = '__msf__'

  TEMPLATE_PATH = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map.html')
  D3_LOCAL_PATH = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'd3.v7.9.0.min.js')
  D3_CDN_TAG    = '<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js" crossorigin="anonymous"></script>'

  def build_graph_data(hosts, db_sessions, traceroute_notes, host_loots)
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

      session_data = host_sessions.map do |s|
        ds = s.datastore.is_a?(Hash) ? s.datastore : {}
        {
          id: s.id,
          type: s.stype || 'unknown',
          via_exploit: s.via_exploit || '',
          via_payload: s.via_payload || '',
          lhost: ds['LHOST'] || '',
          lport: ds['LPORT'] || '',
          opened_at: s.opened_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
          closed_at: s.closed_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
          active: s.closed_at.nil?
        }
      end

      service_data = host.services.map do |svc|
        { port: svc.port, proto: svc.proto, name: svc.name || '', state: svc.state || '' }
      end.sort_by { |s| s[:port] }

      loot_data = (loot_by_host[host.id] || []).map do |l|
        {
          ltype: l.ltype || '',
          name: l.name || '',
          info: l.info || '',
          content_type: l.content_type || '',
          path: l.path || ''
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
    template = File.read(TEMPLATE_PATH)
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
      .sub('%%NODES%%', JSON.generate(nodes))
      .sub('%%LINKS%%', JSON.generate(links))
  end
end
