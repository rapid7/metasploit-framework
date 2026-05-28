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
        'Name' => 'Network Topology/Graph Live Viewer',
        'Description' => %q{
          Starts a lightweight HTTP server that serves an interactive, auto-refreshing
          network graph visualization. The browser polls /api/data at a configurable
          interval; new and changed nodes are highlighted and logged in the UI.
          Open the printed URL in any modern browser. Press Ctrl+C to stop.
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
        OptString.new('SRVHOST', [true, 'Address to bind the HTTP server', '127.0.0.1']),
        OptPort.new('SRVPORT',   [true, 'Port for the HTTP server', 7777]),
        OptInt.new('INTERVAL',   [true, 'Seconds between graph refreshes in the browser', 30]),
        OptInt.new('LIMIT_SESSION', [false, 'Max sessions to include per host (0 = unlimited)', 0]),
        OptInt.new('LIMIT_LOOT',    [false, 'Max loot items to include per host (0 = unlimited)', 0]),
        OptInt.new('LIMIT_CRED',    [false, 'Max credentials to include per host (0 = unlimited)', 0])
      ]
    )
  end

  def run
    fail_with(Failure::BadConfig, 'No database connected.') unless framework.db.active

    host     = datastore['SRVHOST']
    port     = datastore['SRVPORT'].to_i
    interval = [datastore['INTERVAL'].to_i, 5].max

    begin
      server = Rex::Proto::Http::Server.new(port, host, false, { 'Msf' => framework })
    rescue Rex::BindFailed => e
      fail_with(Failure::BadConfig, "Could not bind #{host}:#{port} — #{e.message}")
    end

    server.add_resource('/',         { 'Proc' => method(:handle_root) })
    server.add_resource('/api/data', { 'Proc' => method(:handle_api_data) })
    server.add_resource('/d3.min.js', { 'Proc' => method(:handle_d3) })

    server.start
    print_good("Live graph at http://#{host}:#{port}/  (refreshes every #{interval}s)")
    print_status('Press Ctrl+C to stop')

    loop { sleep 1 }
  rescue ::Interrupt
    print_status('Server stopped.')
  ensure
    server&.stop rescue nil
  end

  private

  LIVE_TEMPLATE_PATH = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map', 'network_map_live_template.html')
  D3_LOCAL_PATH      = File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map', 'd3.v7.9.0.min.js')
  D3_CDN_URL         = 'https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js'

  def handle_root(cli, _request)
    interval_ms = [datastore['INTERVAL'].to_i, 5].max * 1000
    html = File.binread(LIVE_TEMPLATE_PATH)
              .force_encoding('UTF-8')
              .sub('%%INTERVAL%%', interval_ms.to_s)
    send_response(cli, html, 'text/html; charset=utf-8')
  rescue Errno::ENOENT
    send_response(cli, 'Template file not found', 'text/plain', 500)
  end

  def handle_api_data(cli, _request)
    ws_data       = load_workspace_data(myworkspace)
    nodes, links  = build_graph_data(
      ws_data,
      session_limit: datastore['LIMIT_SESSION'].to_i,
      loot_limit:    datastore['LIMIT_LOOT'].to_i,
      cred_limit:    datastore['LIMIT_CRED'].to_i
    )
    json = JSON.generate(utf8_sanitize({ nodes: nodes, links: links }))
    send_response(cli, json, 'application/json')
  rescue StandardError => e
    vprint_error("API data error: #{e.class}: #{e.message}")
    send_response(cli, JSON.generate({ error: e.message }), 'application/json', 500)
  end

  def handle_d3(cli, _request)
    if File.exist?(D3_LOCAL_PATH)
      send_response(cli, File.binread(D3_LOCAL_PATH), 'application/javascript')
    else
      redirect = Rex::Proto::Http::Response.new(302, 'Found')
      redirect['Location'] = D3_CDN_URL
      cli.send_response(redirect)
    end
  end

  def send_response(cli, body, content_type, code = 200)
    resp = Rex::Proto::Http::Response.new(code, code == 200 ? 'OK' : 'Error')
    resp['Content-Type']                = content_type
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Cache-Control']               = 'no-store'
    resp.body = body.encode('binary', invalid: :replace, undef: :replace)
    cli.send_response(resp)
  end
end
