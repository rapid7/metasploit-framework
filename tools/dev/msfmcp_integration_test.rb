#!/usr/bin/env ruby
# frozen_string_literal: true

#
# End-to-end integration test for the Metasploit MCP server (msfmcpd).
#
# Acts as an HTTP client that drives the MCP Streamable HTTP transport,
# exercising the full request lifecycle (initialize, tools/list, tools/call)
# against every registered tool. Mirrors what the MCP Inspector does, but
# scripted and assertion-driven so it can run in CI or as a smoke test.
#
# The msfmcpd HTTP transport and the Metasploit RPC server are expected to
# already be running. This script will not start either of them.
#
# Examples:
#
#   # Smoke test against a freshly started msfmcpd printing its token
#   ruby tools/dev/msfmcp_integration_test.rb \
#     --url http://127.0.0.1:3000 \
#     --token "$MSF_MCP_TOKEN"
#
#   # Include the dangerous-tool execution paths
#   ruby tools/dev/msfmcp_integration_test.rb \
#     --url http://127.0.0.1:3000 \
#     --token "$MSF_MCP_TOKEN" \
#     --enable-dangerous \
#     --rhost 192.0.2.10 --lhost 192.0.2.20 --lport 4444
#
#   # Override the modules / datastore options used by the dangerous tests
#   ruby tools/dev/msfmcp_integration_test.rb \
#     --token "$MSF_MCP_TOKEN" --enable-dangerous \
#     --check-module   exploit:linux/http/some_module \
#     --check-option   RHOSTS=192.0.2.10 --check-option RPORT=8080 \
#     --execute-module auxiliary/scanner/http/http_version \
#     --execute-option RHOSTS=192.0.2.0/24 --execute-option THREADS=10
#
#   # Run only tests whose name matches a pattern. The filter matches against
#   # "<Section> :: <test name>", so you can filter by section or by test.
#   ruby tools/dev/msfmcp_integration_test.rb --token "$T" --filter session
#   ruby tools/dev/msfmcp_integration_test.rb --token "$T" --filter 'Full exploit lifecycle'
#

require 'json'
require 'net/http'
require 'optparse'
require 'securerandom'
require 'uri'

# ----------------------------------------------------------------------------
# Minimal MCP Streamable HTTP client
# ----------------------------------------------------------------------------
class McpHttpClient
  PROTOCOL_VERSION = '2025-11-25'
  ACCEPT = 'application/json, text/event-stream'
  CONTENT_TYPE = 'application/json'

  attr_reader :session_id, :server_info
  attr_accessor :debug

  def initialize(url:, token: nil, open_timeout: 5, read_timeout: 60, debug: false)
    @uri = URI(url)
    raise ArgumentError, "URL must be http(s): #{url}" unless %w[http https].include?(@uri.scheme)

    @http = Net::HTTP.new(@uri.host, @uri.port)
    @http.use_ssl = (@uri.scheme == 'https')
    @http.open_timeout = open_timeout
    @http.read_timeout = read_timeout
    @token = token
    @next_id = 0
    @debug = debug
  end

  def initialize_session!
    payload = {
      jsonrpc: '2.0',
      id: next_id,
      method: 'initialize',
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'msfmcp-integration-test', version: '1.0' }
      }
    }
    response = post_json(payload)
    @session_id = response.http_response['mcp-session-id'] || response.http_response['Mcp-Session-Id']
    raise 'Server did not return Mcp-Session-Id header on initialize' unless @session_id

    body = response.parsed_body
    raise "initialize failed: #{body.inspect}" unless body.is_a?(Hash) && body['result']

    @server_info = body['result']
    send_notification('notifications/initialized')
    @server_info
  end

  def list_tools
    call_method('tools/list')
  end

  def call_tool(name, arguments = {})
    response = call_method('tools/call', { name: name, arguments: arguments })
    # The MCP server uses a single shared token bucket (burst defaults to 10).
    # Integration tests fire calls back to back, so we transparently retry
    # once when we hit the limit instead of forcing every test to think
    # about pacing.
    retry_after = rate_limit_retry_after(response)
    if retry_after
      sleep(retry_after)
      response = call_method('tools/call', { name: name, arguments: arguments })
    end
    response
  end

  def send_notification(method, params = nil)
    payload = { jsonrpc: '2.0', method: method }
    payload[:params] = params if params
    post_json(payload, allow_empty: true)
  end

  def call_method(method, params = nil)
    payload = { jsonrpc: '2.0', id: next_id, method: method }
    payload[:params] = params if params
    post_json(payload).parsed_body
  end

  # Returns the number of seconds to wait, or nil if the response is not a
  # rate-limit error. Rate-limit failures come back as tool responses with
  # `isError: true` and a message of the form "Rate limit exceeded. Retry
  # after N seconds.".
  def rate_limit_retry_after(response)
    return nil unless response.is_a?(Hash)
    return nil unless response.dig('result', 'isError')

    text = response.dig('result', 'content')&.first&.dig('text').to_s
    return nil unless text.include?('Rate limit exceeded')

    match = text.match(/Retry after (\d+) seconds?/i)
    match ? match[1].to_i + 1 : 2
  end

  def terminate_session!
    return unless @session_id

    req = Net::HTTP::Delete.new(@uri.request_uri)
    req['Mcp-Session-Id'] = @session_id
    req['Authorization'] = "Bearer #{@token}" if @token
    @http.request(req)
    @session_id = nil
  end

  # Issue a raw request without the convenience defaults (used to test auth
  # failures, malformed payloads, etc.).
  def raw_post(body, headers: {})
    req = Net::HTTP::Post.new(@uri.request_uri)
    { 'Accept' => ACCEPT, 'Content-Type' => CONTENT_TYPE }.each { |k, v| req[k] = v }
    headers.each { |k, v| req[k] = v }
    req.body = body
    @http.request(req)
  end

  private

  def next_id
    @next_id += 1
  end

  def post_json(payload, allow_empty: false)
    req = Net::HTTP::Post.new(@uri.request_uri)
    req['Accept'] = ACCEPT
    req['Content-Type'] = CONTENT_TYPE
    req['Authorization'] = "Bearer #{@token}" if @token
    req['Mcp-Session-Id'] = @session_id if @session_id
    req.body = JSON.generate(payload)

    debug_log_request(req)
    http_response = @http.request(req)
    debug_log_response(http_response)
    RawResponse.new(http_response, allow_empty: allow_empty)
  end

  def debug_log_request(req)
    return unless @debug

    warn Color.cyan("--> #{req.method} #{@uri}")
    req.each_header do |k, v|
      # Redact the auth token but show that it was sent.
      value = (k.downcase == 'authorization') ? v.sub(/Bearer .+/, 'Bearer <redacted>') : v
      warn Color.cyan("    #{k}: #{value}")
    end
    warn Color.cyan("    body: #{pretty_json(req.body)}") if req.body && !req.body.empty?
  end

  def debug_log_response(http_response)
    return unless @debug

    warn Color.yellow("<-- HTTP #{http_response.code}")
    http_response.each_header { |k, v| warn Color.yellow("    #{k}: #{v}") }
    body = http_response.body.to_s
    warn Color.yellow("    body: #{pretty_json(body)}") unless body.empty?
  end

  def pretty_json(raw)
    JSON.pretty_generate(JSON.parse(raw))
  rescue StandardError
    raw
  end
end

# Wraps a Net::HTTPResponse and parses the body, transparently handling either
# `application/json` or `text/event-stream` (SSE) responses produced by the
# StreamableHTTPTransport.
class RawResponse
  attr_reader :http_response

  def initialize(http_response, allow_empty: false)
    @http_response = http_response
    @allow_empty = allow_empty
  end

  def status
    @http_response.code.to_i
  end

  def content_type
    @http_response['Content-Type'].to_s.split(';').first&.strip
  end

  def parsed_body
    body = @http_response.body.to_s
    if body.empty?
      return nil if @allow_empty

      raise "Empty response body (HTTP #{status})"
    end

    case content_type
    when 'application/json'
      JSON.parse(body)
    when 'text/event-stream'
      parse_sse(body)
    else
      JSON.parse(body)
    end
  rescue JSON::ParserError => e
    raise "Could not parse response (HTTP #{status}, type=#{content_type}): #{e.message}\n#{body}"
  end

  private

  # Extract the first `data:` payload from an SSE stream. The MCP transport
  # only emits a single event per request/response, so this is sufficient.
  def parse_sse(body)
    body.each_line do |line|
      line = line.chomp
      next unless line.start_with?('data:')

      return JSON.parse(line.sub(/^data:\s*/, ''))
    end
    raise "No `data:` line in SSE response body:\n#{body}"
  end
end

# ----------------------------------------------------------------------------
# Test framework
# ----------------------------------------------------------------------------
module Color
  def self.red(s) = "\e[31m#{s}\e[0m"
  def self.green(s) = "\e[32m#{s}\e[0m"
  def self.yellow(s) = "\e[33m#{s}\e[0m"
  def self.cyan(s) = "\e[36m#{s}\e[0m"
  def self.bold(s) = "\e[1m#{s}\e[0m"
end

class TestRunner
  Result = Struct.new(:name, :status, :message, :duration) do
    def passed? = status == :pass
    def failed? = status == :fail
    def skipped? = status == :skip
  end

  attr_reader :results

  def initialize(filter: nil, verbose: false, debug: false)
    @filter = filter
    @verbose = verbose
    @debug = debug
    @results = []
    @current_section = nil
    @section_printed = false
  end

  def run(name)
    qualified = @current_section ? "#{@current_section} :: #{name}" : name
    return if @filter && !qualified.match?(@filter)

    print_section_header
    warn Color.bold(Color.cyan("\n-- #{name} --")) if @debug
    started = Time.now
    begin
      yield
      record(name, :pass, nil, Time.now - started)
    rescue SkipTest => e
      record(name, :skip, e.message, Time.now - started)
    rescue AssertionFailed => e
      record(name, :fail, e.message, Time.now - started)
    rescue StandardError => e
      record(name, :fail, "#{e.class}: #{e.message}", Time.now - started)
    end
  end

  def section(title)
    @current_section = title
    @section_printed = false
    return if @filter # header prints lazily so filtered runs only show sections that have matches

    puts
    puts Color.bold(Color.cyan("== #{title} =="))
    @section_printed = true
  end

  def print_section_header
    return if @section_printed || @current_section.nil?

    puts
    puts Color.bold(Color.cyan("== #{@current_section} =="))
    @section_printed = true
  end

  def summary
    pass = @results.count(&:passed?)
    fail = @results.count(&:failed?)
    skip = @results.count(&:skipped?)
    puts
    puts Color.bold("Results: #{pass} passed, #{fail} failed, #{skip} skipped (#{@results.size} total)")
    fail.zero?
  end

  private

  def record(name, status, message, duration)
    @results << Result.new(name, status, message, duration)
    label = case status
            when :pass then Color.green('PASS')
            when :fail then Color.red('FAIL')
            when :skip then Color.yellow('SKIP')
            end
    line = format('  [%s] %-60s %.3fs', label, name, duration)
    line += "\n         #{message}" if message
    puts line
  end
end

class SkipTest < StandardError; end
class AssertionFailed < StandardError; end

module Assertions
  def assert(condition, message = 'assertion failed')
    raise AssertionFailed, message unless condition
  end

  def assert_equal(expected, actual, message = nil)
    return if expected == actual

    raise AssertionFailed, message || "expected #{expected.inspect}, got #{actual.inspect}"
  end

  def assert_includes(collection, value, message = nil)
    return if collection.include?(value)

    raise AssertionFailed, message || "expected #{collection.inspect} to include #{value.inspect}"
  end

  def assert_match(pattern, string, message = nil)
    return if string.to_s.match?(pattern)

    raise AssertionFailed, message || "expected #{string.inspect} to match #{pattern.inspect}"
  end

  # JSON-RPC level error (transport returned a JSON-RPC error envelope).
  def assert_rpc_error(response, code: nil)
    assert response.is_a?(Hash), "expected response Hash, got #{response.class}"
    assert response['error'], "expected JSON-RPC error, got: #{response.inspect}"
    if code
      assert_equal code, response.dig('error', 'code'),
                   "expected error code #{code}, got #{response.dig('error', 'code').inspect}"
    end
  end

  # Successful tool response (no `isError`).
  def assert_tool_success(response)
    assert response.is_a?(Hash), "expected Hash, got #{response.class}"
    assert response['result'], "expected result key, got: #{response.inspect}"
    is_error = response.dig('result', 'isError')
    assert !is_error,
           "expected tool success, got isError=true: #{response.dig('result', 'content')&.first&.dig('text')}"
  end

  # Tool returned a structured error (`isError: true`) -- the typical response
  # for validation failures, gated dangerous tools, etc.
  def assert_tool_error(response, contains: nil)
    assert response.is_a?(Hash), "expected Hash, got #{response.class}"
    assert response['result'], "expected result key, got: #{response.inspect}"
    assert_equal true, response.dig('result', 'isError'),
                 "expected isError=true, got: #{response.inspect}"
    return unless contains

    text = response.dig('result', 'content')&.first&.dig('text').to_s
    assert text.include?(contains), "expected error text to include #{contains.inspect}, got #{text.inspect}"
  end
end

# ----------------------------------------------------------------------------
# Test suites
# ----------------------------------------------------------------------------
class IntegrationTests
  include Assertions

  EXPECTED_TOOLS = %w[
    msf_search_modules
    msf_module_info
    msf_module_execute
    msf_module_check
    msf_module_results
    msf_running_stats
    msf_host_info
    msf_service_info
    msf_vulnerability_info
    msf_note_info
    msf_credential_info
    msf_loot_info
    msf_session_list
    msf_session_stop
    msf_session_read
    msf_session_write
  ].freeze

  DANGEROUS_TOOLS = %w[msf_module_execute msf_module_check msf_session_stop msf_session_write].freeze

  DEFAULT_CHECK_MODULE   = 'exploit:windows/smb/ms17_010_eternalblue'
  DEFAULT_EXECUTE_MODULE = 'auxiliary:scanner/portscan/tcp'

  def initialize(client:, runner:, options:)
    @client = client
    @runner = runner
    @options = options
  end

  def run_all
    test_protocol
    test_tools_list
    test_read_only_happy_paths
    test_input_validation_errors
    test_dangerous_mode_gate
    test_dangerous_mode_execution if @options[:dangerous]
    test_exploit_lifecycle if @options[:dangerous]
    test_protocol_violations
  end

  # --- Protocol -----------------------------------------------------------

  def test_protocol
    @runner.section('Protocol')

    @runner.run('initialize negotiates protocol version') do
      info = @client.server_info
      assert_includes %w[2025-11-25 2025-06-18 2025-03-26 2024-11-05],
                      info['protocolVersion']
      assert_equal 'msfmcp', info.dig('serverInfo', 'name')
      assert info.dig('serverInfo', 'version').is_a?(String), 'version should be a string'
    end
  end

  # --- tools/list ---------------------------------------------------------

  def test_tools_list
    @runner.section('tools/list')

    @runner.run('tools/list returns all 16 registered tools') do
      response = @client.list_tools
      assert_tool_success(response) if response.dig('result', 'isError')
      tools = response.dig('result', 'tools') || []
      names = tools.map { |t| t['name'] }
      EXPECTED_TOOLS.each do |expected|
        assert_includes names, expected
      end
      assert_equal EXPECTED_TOOLS.size, names.size,
                   "expected #{EXPECTED_TOOLS.size} tools, got #{names.size}: #{names.inspect}"
    end

    @runner.run('tools/list flags dangerous tools via annotations') do
      tools = @client.list_tools.dig('result', 'tools') || []
      DANGEROUS_TOOLS.each do |name|
        tool = tools.find { |t| t['name'] == name }
        assert tool, "missing dangerous tool: #{name}"
        # MCP SDK serializes annotations under "annotations". Tools without
        # destructive_hint=true would default to false.
        assert_equal true, tool.dig('annotations', 'destructiveHint'),
                     "#{name} should have destructiveHint=true"
      end
    end
  end

  # --- Read-only tool happy paths -----------------------------------------

  def test_read_only_happy_paths
    @runner.section('Read-only tools (happy path)')

    @runner.run('msf_search_modules returns results for a common query') do
      r = @client.call_tool('msf_search_modules', { query: 'ms17_010', limit: 5 })
      assert_tool_success(r)
      data = parse_tool_data(r)
      assert data[:data].is_a?(Array), 'expected data array'
    end

    @runner.run('msf_module_info returns metadata for a known module') do
      r = @client.call_tool('msf_module_info',
                            { type: 'exploit', name: 'windows/smb/ms17_010_eternalblue' })
      assert_tool_success(r)
      data = parse_tool_data(r)
      assert data[:data][:fullname].to_s.include?('ms17_010'),
             "unexpected fullname: #{data[:data][:fullname].inspect}"
    end

    @runner.run('msf_running_stats returns counters') do
      r = @client.call_tool('msf_running_stats')
      assert_tool_success(r)
      data = parse_tool_data(r)
      %i[waiting running results].each do |k|
        assert data[:data].key?(k), "missing key #{k}"
        assert data[:data][k].is_a?(Array), "expected #{k} to be an Array"
      end
    end

    @runner.run('msf_session_list returns a hash keyed by session id') do
      r = @client.call_tool('msf_session_list')
      assert_tool_success(r)
      data = parse_tool_data(r)
      assert data[:data].is_a?(Hash), "expected data Hash, got #{data[:data].class}"
      assert data[:metadata][:total_sessions].is_a?(Integer), 'expected total_sessions integer'
    end

    # DB-backed tools: succeed regardless of whether records exist.
    %w[msf_host_info msf_service_info msf_vulnerability_info
       msf_note_info msf_credential_info msf_loot_info].each do |name|
      @runner.run("#{name} returns a (possibly empty) listing") do
        r = @client.call_tool(name, default_db_query_for(name))
        # If no DB is connected the tool returns an isError; tolerate that.
        if r.dig('result', 'isError')
          text = r.dig('result', 'content')&.first&.dig('text').to_s
          if text.match?(/database|workspace/i)
            raise SkipTest, "no database/workspace available: #{text}"
          end

          raise AssertionFailed, "unexpected tool error: #{text}"
        end
        data = parse_tool_data(r)
        assert data[:data].is_a?(Array), 'expected data array'
      end
    end

    @runner.run('msf_module_results returns not-found for a random UUID') do
      r = @client.call_tool('msf_module_results', { uuid: SecureRandom.alphanumeric(24) })
      # Unknown UUID -> isError with a 'not found' message.
      assert_tool_error(r)
    end
  end

  # --- Validation errors --------------------------------------------------

  def test_input_validation_errors
    @runner.section('Input validation')

    @runner.run('msf_search_modules rejects empty query') do
      r = @client.call_tool('msf_search_modules', { query: '' })
      assert response_indicates_validation_error?(r),
             "expected validation error, got: #{r.inspect}"
    end

    @runner.run('msf_module_info rejects an invalid module type') do
      r = @client.call_tool('msf_module_info',
                            { type: 'wat', name: 'windows/smb/ms17_010_eternalblue' })
      assert response_indicates_validation_error?(r),
             "expected validation error, got: #{r.inspect}"
    end

    @runner.run('msf_host_info rejects an invalid IP address') do
      r = @client.call_tool('msf_host_info', { address: 'not.an.ip' })
      assert response_indicates_validation_error?(r),
             "expected validation error, got: #{r.inspect}"
    end

    @runner.run('msf_module_results rejects a malformed UUID') do
      r = @client.call_tool('msf_module_results', { uuid: 'too-short' })
      assert response_indicates_validation_error?(r),
             "expected validation error, got: #{r.inspect}"
    end

    @runner.run('tools/call rejects unknown tool name') do
      response = @client.call_tool('msf_does_not_exist', {})
      # SDK either returns an isError tool response or an RPC error envelope.
      # The MCP Ruby SDK currently returns -32602 with the human-readable
      # detail in `error.data` ("Tool not found: ..."), so check there too.
      rpc_message = response.dig('error', 'message').to_s
      rpc_data    = response.dig('error', 'data').to_s
      ok = response.dig('result', 'isError') ||
           rpc_message.match?(/tool|method|not found|invalid/i) ||
           rpc_data.match?(/tool|method|not found/i)
      assert ok, "expected error for unknown tool, got: #{response.inspect}"
    end
  end

  # --- Dangerous mode gate ------------------------------------------------

  def test_dangerous_mode_gate
    return if @options[:dangerous]

    @runner.section('Dangerous tools (gate closed)')

    DANGEROUS_TOOLS.each do |name|
      @runner.run("#{name} is gated when dangerous mode is disabled") do
        r = @client.call_tool(name, minimal_args_for(name))
        assert_tool_error(r, contains: 'dangerous actions mode')
      end
    end
  end

  # --- Dangerous mode execution -------------------------------------------

  def test_dangerous_mode_execution
    @runner.section('Dangerous tools (gate open)')

    @runner.run('msf_module_check executes against the configured target') do
      type, name = split_module_spec(@options[:check_module] || DEFAULT_CHECK_MODULE)
      defaults = {}
      defaults['RHOSTS'] = @options[:rhost] if @options[:rhost]
      tool_options = merge_options(defaults, @options[:check_option_overrides])
      if tool_options.empty?
        raise SkipTest, 'provide --rhost or --check-option to set required datastore options'
      end

      r = @client.call_tool('msf_module_check',
                            { type: type, name: name, options: tool_options })
      # We don't require Vulnerable/Safe, only that the gate let us through
      # and the call did not produce a structural error.
      assert_tool_success(r)
    end

    @runner.run('msf_module_execute launches a module') do
      type, name = split_module_spec(@options[:execute_module] || DEFAULT_EXECUTE_MODULE)
      if type == 'exploit'
        raise SkipTest, 'covered by full exploit lifecycle test (avoids handler contention)'
      end

      # When the user keeps the bundled default module, apply its companion
      # defaults so the test is runnable with just --rhost.
      defaults = @options[:execute_module].nil? ? { 'PORTS' => '22' } : {}
      defaults['RHOSTS'] = @options[:rhost] if @options[:rhost]
      defaults['LHOST']  = @options[:lhost] if @options[:lhost]
      defaults['LPORT']  = @options[:lport] if @options[:lport]
      tool_options = merge_options(defaults, @options[:execute_option_overrides])
      if tool_options.empty?
        raise SkipTest, 'provide --rhost, --lhost/--lport, or --execute-option to set required datastore options'
      end

      r = @client.call_tool('msf_module_execute',
                            { type: type, name: name, options: tool_options })
      assert_tool_success(r)
      data = parse_tool_data(r)
      assert data[:data][:job_id], 'expected job_id'
      assert data[:data][:uuid], 'expected uuid'
    end

    @runner.run('msf_session_stop rejects a non-existent session id') do
      r = @client.call_tool('msf_session_stop', { session_id: 99_999 })
      # 'Not found' from the RPC counts as a tool error response.
      assert_tool_error(r)
    end

    @runner.run('msf_session_write rejects a non-existent session id') do
      r = @client.call_tool('msf_session_write',
                            { session_id: 99_999, data: 'whoami' })
      assert_tool_error(r)
    end
  end

  # --- Full exploit lifecycle ---------------------------------------------
  #
  # Sequential polling flow (fails fast on explicit error signals):
  #
  #   1. msf_module_execute                                 -> capture uuid
  #   2. msf_running_stats (poll until uuid in :results)    -> run finished
  #   3. msf_module_results (poll until 'session N opened') -> capture SID
  #   4. msf_session_list                                   -> confirm SID
  #   5. msf_session_write (type-appropriate probe command)
  #   6. msf_session_read (poll until probe output matches)
  #   7. msf_session_stop + msf_session_list                -> confirm cleanup
  #
  # Only runs when the module under test is an exploit -- other module types
  # don't necessarily open a session.
  def test_exploit_lifecycle
    type, name = split_module_spec(@options[:execute_module] || DEFAULT_EXECUTE_MODULE)

    @runner.section('Full exploit lifecycle')

    unless type == 'exploit'
      @runner.run("skipped for non-exploit module (#{type}:#{name})") do
        raise SkipTest, "module type is #{type.inspect}, pass --execute-module exploit:..."
      end
      return
    end

    tool_options = build_execute_options
    if tool_options.empty?
      @runner.run('exploit lifecycle') do
        raise SkipTest, 'provide --rhost, --lhost/--lport, or --execute-option to set required datastore options'
      end
      return
    end

    exploit_uuid = nil
    session_id = nil
    session_type = nil
    probe = nil

    # Step 1: launch the exploit.
    @runner.run("msf_module_execute launches exploit #{name}") do
      r = @client.call_tool('msf_module_execute',
                            { type: type, name: name, options: tool_options })
      assert_tool_success(r)
      data = parse_tool_data(r)
      exploit_uuid = data[:data][:uuid]
      assert exploit_uuid, 'expected uuid'
      assert data[:data][:job_id], 'expected job_id'
    end

    unless exploit_uuid
      @runner.run('exploit lifecycle aborted') do
        raise SkipTest, 'no uuid returned from msf_module_execute'
      end
      return
    end

    # Step 2: wait for the run to complete (uuid appears in :results).
    @runner.run("msf_running_stats reports run #{exploit_uuid} finished") do
      done = poll_until(
        timeout: @options[:exploit_timeout],
        predicate: ->(data) { Array(data[:data][:results]).include?(exploit_uuid) }
      ) { @client.call_tool('msf_running_stats') }
      assert done, "uuid #{exploit_uuid} not in running_stats.results after #{@options[:exploit_timeout]}s"
    end

    # Step 3: poll the run's result text for the 'session N opened' line.
    # Fail fast if the result indicates the module errored or explicitly
    # reports that no session was created.
    @runner.run('msf_module_results reports a session-opened line') do
      last_result_text = nil
      outcome = poll_until(
        timeout: 30,
        predicate: lambda do |data|
          status = data[:data][:status].to_s
          result_text = data[:data][:result].to_s
          last_result_text = result_text

          if status == 'errored'
            raise AssertionFailed, "module run errored: #{data[:data][:error].inspect}"
          end
          if NO_SESSION_PATTERNS.any? { |pat| result_text.match?(pat) }
            raise AssertionFailed, "module reported no session opened: #{result_text.inspect}"
          end

          result_text.match?(SESSION_OPENED_PATTERN)
        end
      ) { @client.call_tool('msf_module_results', { uuid: exploit_uuid }) }

      unless outcome
        raise AssertionFailed,
              "no 'session opened' line detected within 30s; last result=#{last_result_text.inspect}"
      end

      session_id = extract_reported_sid(outcome[:data][:result].to_s)
      assert session_id, "could not parse SID from result: #{outcome[:data][:result].inspect}"
    end

    unless session_id
      @runner.run('session interaction skipped') do
        raise SkipTest, 'no session opened -- cannot exercise interactive tools'
      end
      return
    end

    # Step 4: confirm the session is in msf_session_list, and capture its
    # type so the probe command can be chosen accordingly.
    @runner.run("msf_session_list contains session #{session_id}") do
      r = @client.call_tool('msf_session_list')
      assert_tool_success(r)
      data = parse_tool_data(r)
      entry = data[:data][session_id.to_s.to_sym]
      assert entry, "session #{session_id} not in list: #{session_ids_from(data).inspect}"
      session_type = entry[:type].to_s
      probe = probe_for(session_type)
    end

    # Step 5: send the type-appropriate probe command.
    @runner.run("msf_session_write sends #{probe[:description]} to #{session_type} session #{session_id}") do
      r = @client.call_tool('msf_session_write',
                            { session_id: session_id, data: probe[:command] })
      assert_tool_success(r)
    end

    # Step 6: poll session_read for the expected output (or, for DB/SMB/LDAP
    # sessions where no universal probe response exists, verify only that
    # the read call succeeds).
    @runner.run("msf_session_read returns expected output from session #{session_id}") do
      if probe[:verify] == :success_only
        r = @client.call_tool('msf_session_read', { session_id: session_id })
        assert_tool_success(r)
      else
        matched = poll_until(
          timeout: 15,
          predicate: ->(data) { probe[:verify].call(data[:data][:data].to_s) }
        ) { @client.call_tool('msf_session_read', { session_id: session_id }) }
        assert matched, "probe output (#{probe[:description]}) not received within 15s for #{session_type} session"
      end
    end

    @runner.run("msf_session_stop terminates session #{session_id}") do
      r = @client.call_tool('msf_session_stop', { session_id: session_id })
      assert_tool_success(r)
    end

    @runner.run("msf_session_list no longer contains session #{session_id}") do
      gone = poll_until(
        timeout: 15,
        predicate: ->(data) { !session_ids_from(data).include?(session_id) }
      ) { @client.call_tool('msf_session_list') }
      assert gone, "session #{session_id} still present after msf_session_stop"
    end
  end

  # --- Transport-level protocol violations --------------------------------

  def test_protocol_violations
    @runner.section('Transport protocol violations')

    @runner.run('POST without Accept header returns 406') do
      response = @client.raw_post(
        JSON.generate(jsonrpc: '2.0', id: 1, method: 'tools/list'),
        headers: { 'Accept' => 'application/json',
                   'Mcp-Session-Id' => @client.session_id }
      )
      assert_equal 406, response.code.to_i
    end

    @runner.run('POST with wrong Content-Type returns 415') do
      response = @client.raw_post(
        '{}',
        headers: { 'Content-Type' => 'text/plain',
                   'Mcp-Session-Id' => @client.session_id }
      )
      assert_equal 415, response.code.to_i
    end

    @runner.run('POST without session ID returns 400') do
      stale_client = McpHttpClient.new(url: @options[:url], token: @options[:token], debug: @options[:debug])
      response = stale_client.raw_post(
        JSON.generate(jsonrpc: '2.0', id: 1, method: 'tools/list')
      )
      assert_equal 400, response.code.to_i
    end

    @runner.run('POST with invalid bearer token returns 401') do
      raise SkipTest, '--token not provided' unless @options[:token]

      bad_client = McpHttpClient.new(url: @options[:url], token: 'wrong-token', debug: @options[:debug])
      response = bad_client.raw_post(
        JSON.generate(jsonrpc: '2.0', id: 1, method: 'tools/list')
      )
      assert_equal 401, response.code.to_i
    end
  end

  private

  # Extract the structured payload from a tools/call success response.
  def parse_tool_data(response)
    structured = response.dig('result', 'structuredContent')
    return symbolize_deeply(structured) if structured

    text = response.dig('result', 'content')&.first&.dig('text')
    symbolize_deeply(JSON.parse(text))
  end

  def symbolize_deeply(obj)
    case obj
    when Hash then obj.each_with_object({}) { |(k, v), h| h[k.to_sym] = symbolize_deeply(v) }
    when Array then obj.map { |v| symbolize_deeply(v) }
    else obj
    end
  end

  def response_indicates_validation_error?(response)
    # Validation errors are returned as tool responses with isError=true.
    return true if response.dig('result', 'isError')
    # SDK schema validation kicks in before our tool runs and returns a
    # JSON-RPC error envelope (-32602 Invalid params).
    return true if response['error']

    false
  end

  # `TYPE:NAME` -> [type, name]. Colon is unambiguous because module names
  # contain forward slashes but never colons.
  def split_module_spec(spec)
    type, name = spec.to_s.split(':', 2)
    if type.nil? || type.empty? || name.nil? || name.empty?
      raise ArgumentError, "invalid module spec #{spec.inspect}, expected TYPE:NAME"
    end

    [type, name]
  end

  # Merge `defaults` with an array of `"KEY=VALUE"` overrides; overrides win.
  def merge_options(defaults, overrides)
    result = defaults.dup
    Array(overrides).each do |entry|
      key, raw_value = entry.to_s.split('=', 2)
      if key.nil? || key.empty? || raw_value.nil?
        raise ArgumentError, "invalid option #{entry.inspect}, expected KEY=VALUE"
      end

      result[key] = coerce_option_value(raw_value)
    end
    result
  end

  # Best-effort coercion so users can write `RPORT=8080` and not have to wrap
  # numeric or boolean values. The MCP module-options schema accepts string,
  # integer, number, boolean, and null, so this widens the accepted forms
  # without breaking string-only options (which round-trip unchanged).
  def coerce_option_value(value)
    case value
    when /\A-?\d+\z/         then value.to_i
    when /\A-?\d+\.\d+\z/    then value.to_f
    when /\Atrue\z/i         then true
    when /\Afalse\z/i        then false
    when /\Anull\z/i, ''     then nil
    else value
    end
  end

  # Assemble the datastore options passed to msf_module_execute. Kept in one
  # place so the standalone execute test and the lifecycle test agree on the
  # precedence rules (defaults < --rhost/--lhost/--lport < --execute-option).
  def build_execute_options
    defaults = @options[:execute_module].nil? ? { 'PORTS' => '22' } : {}
    defaults['RHOSTS'] = @options[:rhost] if @options[:rhost]
    defaults['LHOST']  = @options[:lhost] if @options[:lhost]
    defaults['LPORT']  = @options[:lport] if @options[:lport]
    merge_options(defaults, @options[:execute_option_overrides])
  end

  # Poll a tool call until the predicate returns truthy or `timeout` seconds
  # elapse. Returns the parsed tool data on success, nil on timeout.
  #
  #   poll_until(timeout: 30, predicate: ->(d) { d[:data][:status] == 'completed' }) do
  #     @client.call_tool('msf_module_results', { uuid: uuid })
  #   end
  #
  def poll_until(timeout:, predicate:, interval: 1)
    deadline = Time.now + timeout
    last_data = nil
    loop do
      response = yield
      assert_tool_success(response)
      last_data = parse_tool_data(response)
      return last_data if predicate.call(last_data)

      break if Time.now >= deadline

      sleep(interval)
    end
    nil
  end

  # session.list returns a hash keyed by session id (as string in JSON).
  # Return them as an Array<Integer> so callers can compute set differences.
  def session_ids_from(tool_data)
    return [] unless tool_data.is_a?(Hash)

    hash = tool_data[:data]
    return [] unless hash.is_a?(Hash)

    hash.keys.filter_map { |k| Integer(k.to_s, 10) rescue nil }
  end

  # Pull the numeric SID out of ExploitDriver's completion message. Works
  # for every session type because the driver formats it uniformly as:
  #   "<session.desc> session <sid> opened (<tunnel>) at <time>"
  # (see lib/msf/core/exploit_driver.rb).
  SESSION_OPENED_PATTERN = /\S+ session (\d+) opened\b/i.freeze

  # Substrings that identify a run that completed without opening a session.
  # Matching any of these short-circuits the module.results poll so the test
  # fails immediately rather than waiting for the poll to time out.
  NO_SESSION_PATTERNS = [
    /but no session was created/i,
    /handler failed to bind/i,
    /exploit aborted due to failure/i
  ].freeze

  def extract_reported_sid(result_text)
    match = result_text.match(SESSION_OPENED_PATTERN)
    match ? match[1].to_i : nil
  end

  # Choose a session-appropriate write/read probe. Returns a hash with:
  #   :description -> short label for test names
  #   :command     -> string to send via msf_session_write
  #   :verify      -> either :success_only (skip content check) or a lambda
  #                    that takes the buffered read output and returns truthy
  #                    when the expected response has arrived.
  #
  # meterpreter uses `sysinfo` (recognisable output). shell / powershell use
  # `echo MSF_PROBE_<nonce>` and match against the nonce so buffered output
  # from earlier commands can't produce a false positive. DB / SMB / LDAP
  # sessions have no universal probe response, so the read is verified only
  # as "did the call succeed" -- semantic checks for those types belong in
  # dedicated tests.
  def probe_for(session_type)
    case session_type.to_s
    when 'meterpreter'
      {
        description: 'sysinfo',
        command: "sysinfo\n",
        verify: ->(buf) { buf.match?(/Computer\s*:|OS\s*:|Meterpreter\s*:|System Language/i) }
      }
    when 'shell', 'powershell'
      marker = "MSF_PROBE_#{SecureRandom.hex(4)}"
      {
        description: "echo #{marker}",
        command: "echo #{marker}\n",
        verify: ->(buf) { buf.include?(marker) }
      }
    else
      {
        description: 'help (success-only)',
        command: "help\n",
        verify: :success_only
      }
    end
  end

  def default_db_query_for(name)
    case name
    when 'msf_host_info'           then { workspace: 'default', limit: 5 }
    when 'msf_service_info'        then { workspace: 'default', limit: 5 }
    when 'msf_vulnerability_info'  then { workspace: 'default', limit: 5 }
    when 'msf_note_info'           then { workspace: 'default', limit: 5 }
    when 'msf_credential_info'     then { workspace: 'default', limit: 5 }
    when 'msf_loot_info'           then { workspace: 'default', limit: 5 }
    else {}
    end
  end

  def minimal_args_for(name)
    case name
    when 'msf_module_execute'
      { type: 'auxiliary', name: 'scanner/portscan/tcp',
        options: { 'RHOSTS' => '192.0.2.10', 'PORTS' => '22' } }
    when 'msf_module_check'
      { type: 'exploit', name: 'windows/smb/ms17_010_eternalblue',
        options: { 'RHOSTS' => '192.0.2.10' } }
    when 'msf_session_stop'  then { session_id: 1 }
    when 'msf_session_write' then { session_id: 1, data: 'whoami' }
    end
  end
end

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
options = {
  url: 'http://127.0.0.1:3000',
  token: ENV['MSF_MCP_TOKEN'],
  dangerous: false,
  verbose: false,
  debug: false,
  filter: nil,
  rhost: nil,
  lhost: nil,
  lport: nil,
  session_id: nil,
  check_module: nil,
  check_option_overrides: [],
  execute_module: nil,
  execute_option_overrides: [],
  exploit_timeout: 120
}

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby tools/dev/msfmcp_integration_test.rb [options]'
  opts.on('--url URL',     'MCP HTTP endpoint (default: http://127.0.0.1:3000)') { |v| options[:url] = v }
  opts.on('--token TOKEN', 'Bearer token (or set $MSF_MCP_TOKEN)')               { |v| options[:token] = v }
  opts.on('--enable-dangerous', 'Run the dangerous-tool execution paths too')    { options[:dangerous] = true }
  opts.on('--rhost IP',    'RHOSTS target for dangerous tests (e.g. 192.0.2.10)') { |v| options[:rhost] = v }
  opts.on('--lhost IP',    'LHOST for payload-bound dangerous tests')            { |v| options[:lhost] = v }
  opts.on('--lport PORT',  Integer, 'LPORT for payload-bound dangerous tests')   { |v| options[:lport] = v }
  opts.on('--check-module SPEC',
          'Module spec for msf_module_check as TYPE:NAME',
          "(default: #{IntegrationTests::DEFAULT_CHECK_MODULE})") { |v| options[:check_module] = v }
  opts.on('--check-option K=V',
          'Datastore option for msf_module_check (repeatable, overrides defaults)') do |v|
    options[:check_option_overrides] << v
  end
  opts.on('--execute-module SPEC',
          'Module spec for msf_module_execute as TYPE:NAME',
          "(default: #{IntegrationTests::DEFAULT_EXECUTE_MODULE})") { |v| options[:execute_module] = v }
  opts.on('--execute-option K=V',
          'Datastore option for msf_module_execute (repeatable, overrides defaults)') do |v|
    options[:execute_option_overrides] << v
  end
  opts.on('--exploit-timeout SEC', Integer,
          'Seconds to wait for the exploit run to reach a terminal state (default: 120)') do |v|
    options[:exploit_timeout] = v
  end
  opts.on('--filter PAT',  Regexp, 'Only run tests whose name matches PAT')      { |v| options[:filter] = v }
  opts.on('-v', '--verbose', 'Print full responses on failure')                  { options[:verbose] = true }
  opts.on('-d', '--debug',
          'Print the full HTTP request/response for every call (succeeds too)') { options[:debug] = true }
  opts.on('-h', '--help', 'Show this help') do
    puts opts
    exit 0
  end
end.parse!

puts Color.bold("msfmcpd integration tests")
puts "  URL              : #{options[:url]}"
puts "  Bearer token     : #{options[:token] ? '(provided)' : '(none)'}"
puts "  Dangerous mode   : #{options[:dangerous] ? 'enabled (execution tests will run)' : 'disabled (gate tests only)'}"
puts "  Filter           : #{options[:filter] || '(none)'}"

client = McpHttpClient.new(url: options[:url], token: options[:token], debug: options[:debug])

begin
  client.initialize_session!
rescue StandardError => e
  warn Color.red("Failed to initialize MCP session: #{e.class}: #{e.message}")
  exit 2
end

runner = TestRunner.new(filter: options[:filter], verbose: options[:verbose], debug: options[:debug])
suite  = IntegrationTests.new(client: client, runner: runner, options: options)

begin
  suite.run_all
ensure
  begin
    client.terminate_session!
  rescue StandardError
    # best-effort
  end
end

exit(runner.summary ? 0 : 1)
