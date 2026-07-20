# frozen_string_literal: true

require 'msf/core/mcp'
require 'tempfile'
require 'json'
require 'rack'

RSpec.describe Msf::MCP::Middleware::RequestLogger do
  let(:log_file) { Tempfile.new(['request_logger_test', '.log']).tap(&:close).path }
  let(:log_source) { Msf::MCP::LOG_SOURCE }

  # A simple Rack app that returns a configurable response
  let(:response_status) { 200 }
  let(:response_headers) { { 'Content-Type' => 'application/json' } }
  let(:response_body) { ['{"jsonrpc":"2.0","id":1,"result":{}}'] }
  let(:inner_app) { ->(_env) { [response_status, response_headers, response_body] } }
  let(:middleware) { described_class.new(inner_app) }

  before do
    deregister_log_source(log_source) if log_source_registered?(log_source)
    register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new(log_file), Rex::Logging::LEV_3)
  end

  after do
    deregister_log_source(log_source) if log_source_registered?(log_source)
    File.delete(log_file) if File.exist?(log_file)
  end

  # Helper: parse the last JSON log entry
  def last_log_entry
    JSON.parse(File.read(log_file).strip.split("\n").last)
  end

  # Helper: build a minimal Rack env for a given HTTP method
  def rack_env_for(method, body: nil, headers: {})
    env = Rack::MockRequest.env_for('http://localhost:3000/mcp', method: method)
    if body
      io = StringIO.new(body)
      env['rack.input'] = io
    end
    headers.each do |key, value|
      rack_key = "HTTP_#{key.upcase.tr('-', '_')}"
      env[rack_key] = value
    end
    env
  end

  describe '#call' do
    it 'delegates to the inner app and returns its response' do
      env = rack_env_for('POST', body: '{"jsonrpc":"2.0","method":"ping","id":1}')
      status, headers, body = middleware.call(env)

      expect(status).to eq(200)
      expect(headers).to eq(response_headers)
      expect(body).to eq(response_body)
    end

    it 'logs after the inner app responds' do
      env = rack_env_for('POST', body: '{"jsonrpc":"2.0","method":"ping","id":1}')
      middleware.call(env)

      expect(File.read(log_file)).not_to be_empty
    end
  end

  describe 'POST requests' do
    context 'with a normal JSON-RPC request' do
      it 'logs at DEBUG level with method and id' do
        body = '{"jsonrpc":"2.0","method":"tools/call","id":42,"params":{"name":"test"}}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        entry = last_log_entry

        expect(entry['severity']).to eq('DEBUG')
        expect(entry['message']).to include('tools/call')
        expect(entry['message']).to include('id=42')
      end

      it 'includes elapsed time in the message' do
        body = '{"jsonrpc":"2.0","method":"ping","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)

        expect(last_log_entry['message']).to match(/\d+(\.\d+)?ms/)
      end

      it 'includes request fields in context' do
        body = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"test"}}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        ctx = last_log_entry['context']

        expect(ctx['request']['method']).to eq('tools/call')
        expect(ctx['request']['id']).to eq(1)
      end

      it 'includes response status in context' do
        body = '{"jsonrpc":"2.0","method":"ping","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        ctx = last_log_entry['context']

        expect(ctx['response']['status']).to eq(200)
      end

      it 'includes response result in context' do
        body = '{"jsonrpc":"2.0","method":"ping","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        ctx = last_log_entry['context']

        expect(ctx['response']['result']).to eq({})
      end
    end

    context 'with a notification (no id)' do
      it 'logs at DEBUG level as a notification' do
        body = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        entry = last_log_entry

        expect(entry['severity']).to eq('DEBUG')
        expect(entry['message']).to include('Notification')
        expect(entry['message']).to include('notifications/initialized')
      end
    end

    context 'with an HTTP error response' do
      let(:response_status) { 400 }
      let(:response_body) { ['{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}'] }

      it 'logs at ERROR level' do
        body = '{"jsonrpc":"2.0","method":"invalid","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        entry = last_log_entry

        expect(entry['severity']).to eq('ERROR')
        expect(entry['message']).to include('400')
        expect(entry['message']).to include('invalid')
      end

      it 'includes error details in response context' do
        body = '{"jsonrpc":"2.0","method":"invalid","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        ctx = last_log_entry['context']

        expect(ctx['response']['error']).to be_a(Hash)
        expect(ctx['response']['error']['message']).to eq('Method not found')
      end
    end

    context 'with invalid JSON in request body' do
      it 'logs with unknown method name' do
        env = rack_env_for('POST', body: 'not valid json{{{')
        middleware.call(env)

        expect(last_log_entry['message']).to include('unknown')
      end
    end

    context 'with empty response body' do
      let(:response_body) { [] }

      it 'does not include result or error in response context' do
        body = '{"jsonrpc":"2.0","method":"ping","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        ctx = last_log_entry['context']

        expect(ctx['response']).not_to have_key('result')
        expect(ctx['response']).not_to have_key('error')
      end
    end

    context 'with non-Array response body (SSE stream)' do
      let(:response_body) { proc { |_| } }

      it 'does not include result or error in response context' do
        body = '{"jsonrpc":"2.0","method":"tools/call","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        ctx = last_log_entry['context']

        expect(ctx['response']).not_to have_key('result')
        expect(ctx['response']).not_to have_key('error')
      end
    end

    context 'with invalid JSON in response body' do
      let(:response_body) { ['not json{{{'] }

      it 'does not include result or error in response context' do
        body = '{"jsonrpc":"2.0","method":"ping","id":1}'
        env = rack_env_for('POST', body: body)
        middleware.call(env)
        ctx = last_log_entry['context']

        expect(ctx['response']).not_to have_key('result')
        expect(ctx['response']).not_to have_key('error')
      end
    end
  end

  describe 'GET requests' do
    it 'logs SSE stream opened at INFO level' do
      env = rack_env_for('GET')
      middleware.call(env)
      entry = last_log_entry

      expect(entry['severity']).to eq('INFO')
      expect(entry['message']).to include('SSE stream opened')
    end

    it 'includes elapsed time' do
      env = rack_env_for('GET')
      middleware.call(env)

      expect(last_log_entry['message']).to match(/\d+(\.\d+)?ms/)
    end

    it 'includes session_id from header when present' do
      env = rack_env_for('GET', headers: { 'Mcp-Session-Id' => 'sess-abc' })
      middleware.call(env)

      expect(last_log_entry['context']['session_id']).to eq('sess-abc')
    end

    it 'includes response status in context' do
      env = rack_env_for('GET')
      middleware.call(env)

      expect(last_log_entry['context']['response']['status']).to eq(200)
    end
  end

  describe 'DELETE requests' do
    it 'logs session deleted at INFO level' do
      env = rack_env_for('DELETE')
      middleware.call(env)
      entry = last_log_entry

      expect(entry['severity']).to eq('INFO')
      expect(entry['message']).to include('Session deleted')
    end
  end

  describe 'other HTTP methods' do
    it 'logs at DEBUG level with method name and status' do
      env = rack_env_for('OPTIONS')
      middleware.call(env)
      entry = last_log_entry

      expect(entry['severity']).to eq('DEBUG')
      expect(entry['message']).to include('OPTIONS')
      expect(entry['message']).to include('200')
    end
  end

  describe 'session ID extraction' do
    it 'extracts session_id from request header' do
      body = '{"jsonrpc":"2.0","method":"ping","id":1}'
      env = rack_env_for('POST', body: body, headers: { 'Mcp-Session-Id' => 'req-sess' })
      middleware.call(env)

      expect(last_log_entry['context']['session_id']).to eq('req-sess')
    end

    it 'falls back to session_id from response header' do
      response_headers['Mcp-Session-Id'] = 'resp-sess'
      body = '{"jsonrpc":"2.0","method":"ping","id":1}'
      env = rack_env_for('POST', body: body)
      middleware.call(env)

      expect(last_log_entry['context']['session_id']).to eq('resp-sess')
    end

    it 'omits session_id when not present' do
      body = '{"jsonrpc":"2.0","method":"ping","id":1}'
      env = rack_env_for('POST', body: body)
      middleware.call(env)

      expect(last_log_entry['context']).not_to have_key('session_id')
    end
  end

  describe 'content type in response context' do
    it 'includes Content-Type when present' do
      env = rack_env_for('GET')
      middleware.call(env)

      expect(last_log_entry['context']['response']['content_type']).to eq('application/json')
    end

    it 'omits Content-Type when not present' do
      response_headers.delete('Content-Type')
      env = rack_env_for('GET')
      middleware.call(env)

      expect(last_log_entry['context']['response']).not_to have_key('content_type')
    end
  end
end
