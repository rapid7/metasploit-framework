# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Server do
  let(:valid_config) do
    {
      msf_api: {
        type: 'messagepack',
        host: 'localhost',
        port: 55553,
        endpoint: '/api/',
        user: 'test_user',
        password: 'test_password'
      },
      rate_limit: {
        requests_per_minute: 60,
        burst_size: 10
      }
    }
  end

  let(:mock_msf_client) do
    instance_double(Msf::MCP::Metasploit::Client).tap do |client|
      allow(client).to receive(:shutdown)
    end
  end

  let(:rate_limiter) do
    Msf::MCP::Security::RateLimiter.new(
      requests_per_minute: valid_config.dig(:rate_limit, :requests_per_minute) || 60,
      burst_size: valid_config.dig(:rate_limit, :burst_size)
    )
  end

  let(:mock_mcp_server) do
    instance_double(::MCP::Server).tap do |server|
      allow(server).to receive(:transport=)
    end
  end

  let(:mock_transport) do
    instance_double(::MCP::Server::Transports::StdioTransport).tap do |transport|
      allow(transport).to receive(:open)
    end
  end

  describe '#initialize' do
    it 'initializes with required dependencies' do
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)

      server = described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
      mcp_server = server.start

      expect(mcp_server.server_context[:msf_client]).to eq(mock_msf_client)
      expect(mcp_server.server_context[:rate_limiter]).to eq(rate_limiter)
    end

    it 'creates MCP server with correct parameters' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          name: 'msfmcp',
          version: Msf::MCP::Application::VERSION,
          tools: be_an(Array),
          server_context: be_a(Hash)
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'registers all MCP tools' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          tools: array_including(
            Msf::MCP::Tools::SearchModules,
            Msf::MCP::Tools::ModuleInfo,
            Msf::MCP::Tools::HostInfo,
            Msf::MCP::Tools::ServiceInfo,
            Msf::MCP::Tools::VulnerabilityInfo,
            Msf::MCP::Tools::NoteInfo,
            Msf::MCP::Tools::CredentialInfo,
            Msf::MCP::Tools::LootInfo
          )
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'creates server context with msf_client and rate_limiter' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_including(
            msf_client: mock_msf_client,
            rate_limiter: rate_limiter
          )
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'does not include config hash in server_context' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_not_including(:config)
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'passes a configuration object with around_request and exception_reporter' do
      expect(::MCP::Server).to receive(:new) do |args|
        config = args[:configuration]
        expect(config).to be_a(::MCP::Configuration)
        expect(config.around_request).to be_a(Proc)
        expect(config.exception_reporter).to be_a(Proc)
        mock_mcp_server
      end

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end
  end

  describe '#start' do
    let(:server) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    context 'with stdio transport' do
      it 'creates stdio transport' do
        expect(::MCP::Server::Transports::StdioTransport).to receive(:new).with(mock_mcp_server).and_return(mock_transport)

        server.start(transport: :stdio)
      end

      it 'opens the transport' do
        allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        expect(mock_transport).to receive(:open)

        server.start(transport: :stdio)
      end

      it 'defaults to stdio when no transport specified' do
        expect(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        server.start
      end
    end

    context 'with http transport' do
      let(:mock_http_transport) do
        instance_double(::MCP::Server::Transports::StreamableHTTPTransport)
      end
      let(:puma_handler) { double('puma_handler') }
      let(:rack_app) { double('rack_app') }

      before do
        # Stub #require to prevent actually loading rack and rack/handler/puma
        allow(server).to receive(:require).with('rack').and_return(true)
        allow(server).to receive(:require).with('rack/handler/puma').and_return(true)

        stub_const('Rack::Handler::Puma', puma_handler)
        stub_const('Rack::Builder', double('Rack::Builder'))

        allow(::MCP::Server::Transports::StreamableHTTPTransport).to receive(:new).and_return(mock_http_transport)
        allow(Rack::Builder).to receive(:new).and_return(rack_app)

        allow(puma_handler).to receive(:run)
      end

      it 'creates http transport' do
        expect(::MCP::Server::Transports::StreamableHTTPTransport).to receive(:new).with(mock_mcp_server)

        server.start(transport: :http, port: 3000)
      end

      it 'starts Puma server via Rack handler' do
        expect(puma_handler).to receive(:run).with(
          anything,  # Rack app
          hash_including(
            Port: 3000,
            Host: 'localhost'
          )
        )

        server.start(transport: :http, port: 3000)
      end

      it 'allows custom port' do
        expect(puma_handler).to receive(:run).with(
          anything,
          hash_including(Port: 8080)
        )

        server.start(transport: :http, port: 8080)
      end

      it 'creates a Rack application' do
        expect(puma_handler).to receive(:run) do |rack_app, options|
          expect(rack_app).to be(rack_app)
          expect(options).to include(Port: 3000, Host: 'localhost')
        end

        server.start(transport: :http, port: 3000)
      end
    end

    context 'with invalid transport' do
      it 'raises ArgumentError' do
        expect {
          server.start(transport: :websocket)
        }.to raise_error(ArgumentError, /Unknown transport.*websocket/)
      end

      it 'error message mentions valid transports' do
        expect {
          server.start(transport: :invalid)
        }.to raise_error(ArgumentError, /stdio.*http/)
      end
    end
  end

  describe '#shutdown' do
    let(:server) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'shuts down the Metasploit client' do
      expect(mock_msf_client).to receive(:shutdown)

      server.shutdown
    end

    it 'handles nil msf_client gracefully' do
      server.instance_variable_set(:@msf_client, nil)

      expect { server.shutdown }.not_to raise_error
    end

    it 'clears mcp_server reference' do
      server.shutdown

      expect(server.instance_variable_get(:@mcp_server)).to be_nil
    end

    it 'can be called multiple times safely' do
      expect {
        server.shutdown
        server.shutdown
      }.not_to raise_error
    end
  end

  describe 'dependency injection' do
    let(:server) do
      # Create server with pre-authenticated client
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end
    let(:mcp_server) { server.start }

    before do
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)
    end

    it 'uses the provided authenticated client' do
      # The provided client should be used
      expect(mcp_server.server_context[:msf_client]).to eq(mock_msf_client)
      expect(mcp_server.server_context[:msf_client].object_id).to eq(mock_msf_client.object_id)
    end

    it 'passes the provided client to server_context' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_including(
            msf_client: mock_msf_client
          )
        )
      ).and_return(mock_mcp_server)

      server
    end

    context 'with a custom rate limiter' do
      let(:rate_limiter) do
        Msf::MCP::Security::RateLimiter.new(
          requests_per_minute: 120,
          burst_size: 20
        )
      end

      it 'uses the provided rate_limiter' do
        expect(mcp_server.server_context[:rate_limiter]).to eq(rate_limiter)
        expect(mcp_server.server_context[:rate_limiter].instance_variable_get(:@requests_per_minute)).to eq(120)
        expect(mcp_server.server_context[:rate_limiter].instance_variable_get(:@burst_size)).to eq(20)
      end
    end
  end

  # Instrumentation and logging tests
  describe 'instrumentation and logging' do
    require 'tempfile'
    require 'json'

    let(:log_file) { Tempfile.new(['test_log', '.log']).tap(&:close).path }

    before do
      if log_source_registered?(Msf::MCP::LOG_SOURCE)
        deregister_log_source(Msf::MCP::LOG_SOURCE)
      end
      register_log_source(
        Msf::MCP::LOG_SOURCE,
        Msf::MCP::Logging::Sinks::JsonFlatfile.new(log_file),
        Rex::Logging::LEV_3
      )
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)
    end

    after do
      if log_source_registered?(Msf::MCP::LOG_SOURCE)
        deregister_log_source(Msf::MCP::LOG_SOURCE)
      end
      File.delete(log_file) if File.exist?(log_file)
    end

    # Helper: parse the last JSON log entry from the file
    def last_log_entry
      JSON.parse(File.read(log_file).strip.split("\n").last)
    end

    let(:server) { described_class.new(msf_client: mock_msf_client, rate_limiter: rate_limiter) }
    let(:mcp_server) { server.start }

    describe 'around_request' do
      it 'is always configured as a Proc' do
        expect(mcp_server.configuration.around_request).to be_a(Proc)
      end

      it 'calls the request handler and returns its result' do
        result = mcp_server.configuration.around_request.call({ tool_name: 'test' }) { { isError: false } }
        expect(result).to eq({ isError: false })
      end

      it 'logs error tool calls with error severity' do
        mcp_server.configuration.around_request.call(
          { method: 'tools/call', tool_name: 'test_tool', error: 'tool_not_found' }
        ) { nil }
        entry = last_log_entry

        expect(entry['severity']).to eq('ERROR')
        expect(entry['message']).to include('MCP Error: tool_not_found')
      end

      it 'logs successful tool calls with info severity' do
        mcp_server.configuration.around_request.call(
          { method: 'tools/call', tool_name: 'search_modules' }
        ) { { isError: false } }
        entry = last_log_entry

        expect(entry['severity']).to eq('INFO')
        expect(entry['message']).to include('Tool call: search_modules')
      end

      it 'logs isError results with error severity' do
        mcp_server.configuration.around_request.call(
          { method: 'tools/call', tool_name: 'test_tool' }
        ) { { isError: true } }
        entry = last_log_entry

        expect(entry['severity']).to eq('ERROR')
        expect(entry['message']).to include('(ERROR)')
      end

      it 'logs via ilog when result is nil and no error' do
        mcp_server.configuration.around_request.call(
          { method: 'tools/call', tool_name: 'test_tool' }
        ) { nil }
        entry = last_log_entry

        expect(entry['severity']).to eq('INFO')
        expect(entry['message']).to include('Tool call: test_tool')
      end

      it 'logs prompt calls' do
        mcp_server.configuration.around_request.call(
          { method: 'prompts/get', prompt_name: 'exploit_suggestion' }
        ) { {} }

        expect(last_log_entry['message']).to include('Prompt call: exploit_suggestion')
      end

      it 'logs resource calls' do
        mcp_server.configuration.around_request.call(
          { method: 'resources/read', resource_uri: 'msf://exploits/windows' }
        ) { {} }

        expect(last_log_entry['message']).to include('Resource call: msf://exploits/windows')
      end

      it 'logs generic method calls' do
        mcp_server.configuration.around_request.call({ method: 'ping' }) { {} }

        expect(last_log_entry['message']).to include('Method call: ping')
      end

      it 'logs fallback message when no specific key is present' do
        mcp_server.configuration.around_request.call({}) { {} }

        expect(last_log_entry['message']).to include('MCP request')
      end
    end

    describe 'exception_reporter' do
      it 'is always configured as a Proc' do
        expect(mcp_server.configuration.exception_reporter).to be_a(Proc)
      end

      it 'is a no-op when called with nil arguments' do
        expect { mcp_server.configuration.exception_reporter.call(nil, nil) }.not_to raise_error
      end

      it 'logs exceptions with error severity' do
        mcp_server.configuration.exception_reporter.call(
          StandardError.new('Something went wrong'),
          { request: '{"method":"tools/call","params":{"name":"msf_search_modules"}}' }
        )
        entry = last_log_entry

        expect(entry['severity']).to eq('ERROR')
        expect(entry['message']).to include('Error during request processing')
      end

      it 'extracts JSON-RPC method name from request context' do
        mcp_server.configuration.exception_reporter.call(
          StandardError.new('fail'),
          { request: '{"method":"tools/call","params":{"name":"test"}}' }
        )

        expect(last_log_entry['message']).to include('(tools/call)')
      end

      it 'logs notification context' do
        mcp_server.configuration.exception_reporter.call(
          RuntimeError.new('Notification failed'),
          { notification: 'notifications/initialized' }
        )
        entry = last_log_entry

        expect(entry['message']).to include('Error during notification processing')
        expect(entry['message']).to include('notifications/initialized')
      end

      it 'logs unknown context type' do
        mcp_server.configuration.exception_reporter.call(StandardError.new('Unknown error'), {})

        expect(last_log_entry['message']).to include('Error during unknown processing')
      end

      it 'handles a non-JSON request value' do
        mcp_server.configuration.exception_reporter.call(
          StandardError.new('Parse error'), { request: 'not valid json' }
        )

        expect(last_log_entry['message']).to include('Error during request processing')
      end
    end
  end
end
