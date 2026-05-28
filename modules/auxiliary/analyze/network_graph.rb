# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::NetworkGraphBuilder

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

    ws      = myworkspace
    ws_data = load_workspace_data(ws)

    hosts            = ws_data[:hosts]
    db_sessions      = ws_data[:db_sessions]
    traceroute_notes = ws_data[:traceroute_notes]
    snmp_by_host     = ws_data[:snmp_by_host]

    print_status('Building network graph:')
    print_status("  Hosts:             #{hosts.length}")
    print_status("  Sessions:          #{db_sessions.length}")
    print_status("  Traceroutes:       #{traceroute_notes.length}")
    print_status("  Loot items:        #{ws_data[:host_loots].length}")
    print_status("  SNMP enriched:     #{snmp_by_host.length}")
    print_status("  Module runs:       #{ws_data[:direct_module_runs].length}")
    print_status("  Credential logins: #{ws_data[:host_cred_logins].length}")

    subnet_to_pivot = {}
    db_sessions.each do |s|
      next unless s.respond_to?(:routes)
      s.routes.each { |r| subnet_to_pivot["#{r.subnet}/#{r.netmask}"] = s.host_id }
    end

    if subnet_to_pivot.empty? && traceroute_notes.empty?
      print_warning('No session routes or traceroute data found. All hosts will appear as directly connected to the MSF node. For better topology, run nmap with --traceroute or add routes via "route add" after obtaining a pivot session.')
    end

    nodes, links = build_graph_data(
      ws_data,
      session_limit: datastore['LIMIT_SESSION'].to_i,
      loot_limit:    datastore['LIMIT_LOOT'].to_i,
      cred_limit:    datastore['LIMIT_CRED'].to_i
    )
    html = generate_html(nodes, links)

    loot_path = store_loot('network.graph', nil, nil, html, 'network_graph.html', 'MSF Network Graph Visualization')
    print_good("Network graph saved to: #{loot_path}")
  end

  private

  TEMPLATE_PATH = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map', 'network_map_template.html')
  D3_LOCAL_PATH = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map', 'd3.v7.9.0.min.js')
  D3_CDN_TAG    = '<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js" crossorigin="anonymous"></script>'

  def generate_html(nodes, links)
    template = File.binread(TEMPLATE_PATH).force_encoding('UTF-8')
    d3_tag   = if datastore['EMBED_JS']
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
end
