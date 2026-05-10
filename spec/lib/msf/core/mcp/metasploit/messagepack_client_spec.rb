# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Metasploit::MessagePackClient do
  let(:host) { 'localhost' }
  let(:port) { 55553 }
  let(:client) { described_class.new(host: host, port: port) }

  describe '#initialize' do
    it 'sets instance variables' do
      expect(client.instance_variable_get(:@host)).to eq(host)
      expect(client.instance_variable_get(:@port)).to eq(port)
      expect(client.instance_variable_get(:@endpoint)).to eq('/api/')
      expect(client.instance_variable_get(:@token)).to be_nil
    end

    it 'defaults ssl to true when not specified' do
      expect(client.instance_variable_get(:@ssl)).to eq(true)
    end

    it 'accepts ssl parameter' do
      client_no_ssl = described_class.new(host: host, port: port, ssl: false)
      expect(client_no_ssl.instance_variable_get(:@ssl)).to eq(false)
    end
  end

  describe 'SSL configuration' do
    let(:http_mock) { instance_double(Net::HTTP) }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_mock)
      allow(http_mock).to receive(:use_ssl=)
      allow(http_mock).to receive(:verify_mode=)
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'test123' }.to_msgpack)
      )
    end

    context 'when ssl is true' do
      let(:client) { described_class.new(host: host, port: port, ssl: true) }

      it 'enables SSL on Net::HTTP client' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end

      it 'sets verify_mode to VERIFY_NONE' do
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end

    context 'when ssl is false' do
      let(:client) { described_class.new(host: host, port: port, ssl: false) }

      it 'disables SSL on Net::HTTP client' do
        expect(http_mock).to receive(:use_ssl=).with(false)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end

      it 'does not set verify_mode' do
        expect(http_mock).not_to receive(:verify_mode=)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end

    context 'with default SSL setting' do
      it 'uses SSL by default' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end

    context 'when explicitly set to true' do
      let(:client) { described_class.new(host: host, port: port, ssl: true) }

      it 'configures HTTPS connection' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end
  end

  describe '#authenticate' do
    it 'sends authentication request with username and password' do
      expect(client).to receive(:send_request).with(['auth.login', 'testuser', 'testpass']).and_return({ 'result' => 'success', 'token' => 'abc123' })

      client.authenticate('testuser', 'testpass')
    end

    it 'stores token from response' do
      allow(client).to receive(:send_request).and_return({ 'result' => 'success', 'token' => 'abc123' })
      token = client.authenticate('testuser', 'testpass')
      expect(token).to eq('abc123')
    end

    it 'raises AuthenticationError when response contains error key' do
      allow(client).to receive(:send_request).and_return({ 'error' => 'Invalid credentials' })

      expect {
        client.authenticate('testuser', 'badpass')
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError, 'Invalid credentials')
    end

    it 'raises AuthenticationError with default message when result is not success' do
      allow(client).to receive(:send_request).and_return({ 'result' => 'failure' })

      expect {
        client.authenticate('testuser', 'testpass')
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError, 'Authentication failed')
    end

    it 'raises AuthenticationError when send_request raises' do
      allow(client).to receive(:send_request).and_raise(Msf::MCP::Metasploit::AuthenticationError, 'Login Failed')

      expect {
        client.authenticate('testuser', 'testpass')
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError, 'Login Failed')
    end
  end

  describe '#call_api' do
    before do
      client.instance_variable_set(:@token, 'abc123')
      allow(client).to receive(:send_request).and_return(['module1', 'module2'])
    end

    it 'sends method call with token and arguments' do
      expect(client).to receive(:send_request).with(['module.search', 'abc123', 'smb']).and_return([])

      client.call_api('module.search', ['smb'])
    end

    it 'returns result from response' do
      result = client.call_api('module.search', ['smb'])
      expect(result).to eq(['module1', 'module2'])
    end

    it 'raises ArgumentError when args is not an Array' do
      expect {
        client.call_api('module.search', 'smb')
      }.to raise_error(ArgumentError, /args must be an Array/)
    end

    it 'raises ArgumentError when args is a Hash' do
      expect {
        client.call_api('module.search', { query: 'smb' })
      }.to raise_error(ArgumentError, /args must be an Array/)
    end

    it 'raises AuthenticationError if no token present and no credentials stored' do
      client.instance_variable_set(:@token, nil)

      expect {
        client.call_api('module.search', ['smb'])
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError, 'Not authenticated')
    end

    it 'raises APIError when response contains error' do
      allow(client).to receive(:send_request).and_raise(Msf::MCP::Metasploit::APIError, 'Method not found')

      expect {
        client.call_api('module.search', ['smb'])
      }.to raise_error(Msf::MCP::Metasploit::APIError, 'Method not found')
    end

    it 'logs via elog before re-raising Msf::MCP::Error subclasses' do
      allow(client).to receive(:send_request).and_raise(Msf::MCP::Metasploit::APIError, 'Method not found')

      expect(client).to receive(:elog).with(hash_including(message: 'MessagePack API call error'), anything, anything)
      expect {
        client.call_api('module.search', ['smb'])
      }.to raise_error(Msf::MCP::Metasploit::APIError)
    end
  end

  describe '#shutdown' do
    it 'clears token from memory' do
      client.instance_variable_set(:@token, 'abc123')
      client.shutdown
      expect(client.instance_variable_get(:@token)).to be_nil
    end

    it 'clears stored credentials' do
      client.instance_variable_set(:@user, 'testuser')
      client.instance_variable_set(:@password, 'testpass')
      client.shutdown
      expect(client.instance_variable_get(:@user)).to be_nil
      expect(client.instance_variable_get(:@password)).to be_nil
    end

    it 'finishes HTTP connection if started' do
      http_mock = double('Net::HTTP')
      allow(http_mock).to receive(:started?).and_return(true)
      allow(http_mock).to receive(:finish)

      client.instance_variable_set(:@http, http_mock)
      client.shutdown

      expect(http_mock).to have_received(:finish)
    end
  end

  describe '#sanitize_request_array' do
    it 'redacts password in auth.login requests' do
      result = client.send(:sanitize_request_array, ['auth.login', 'admin', 's3cret'])
      expect(result).to eq(['auth.login', 'admin', '[REDACTED]'])
    end

    it 'redacts token in API call requests' do
      result = client.send(:sanitize_request_array, ['module.search', 'tok_abc123', 'smb'])
      expect(result).to eq(['module.search', '[REDACTED]', 'smb'])
    end

    it 'does not mutate the original array' do
      original = ['auth.login', 'admin', 's3cret']
      client.send(:sanitize_request_array, original)
      expect(original).to eq(['auth.login', 'admin', 's3cret'])
    end

    it 'handles single-element arrays' do
      result = client.send(:sanitize_request_array, ['auth.logout'])
      expect(result).to eq(['auth.logout'])
    end
  end

  describe 'debug logging' do
    let(:http_mock) { instance_double(Net::HTTP) }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_mock)
      allow(http_mock).to receive(:use_ssl=)
    end

    it 'does not raise when no Rex sink is registered' do
      client_no_ssl = described_class.new(host: host, port: port, ssl: false)
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'abc' }.to_msgpack)
      )
      expect { client_no_ssl.authenticate('user', 'pass') }.not_to raise_error
    end

    it 'calls dlog for request and response' do
      client_no_ssl = described_class.new(host: host, port: port, ssl: false)
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'abc' }.to_msgpack)
      )

      expect(client_no_ssl).to receive(:dlog).with(hash_including(message: 'MessagePack request'), anything, anything).ordered
      expect(client_no_ssl).to receive(:dlog).with(hash_including(message: 'MessagePack response'), anything, anything).ordered

      client_no_ssl.authenticate('user', 'pass')
    end
  end

  describe 'automatic re-authentication' do
    before do
      # Initial authentication
      allow(client).to receive(:send_request).with(['auth.login', 'testuser', 'testpass']).and_return(
        { 'result' => 'success', 'token' => 'initial_token' }
      )

      client.authenticate('testuser', 'testpass')
    end

    it 'automatically re-authenticates on invalid token error' do
      call_count = 0

      allow(client).to receive(:send_request) do |request_array|
        call_count += 1

        case call_count
        when 1
          # First API call raises AuthenticationError (simulating HTTP 401)
          raise Msf::MCP::Metasploit::AuthenticationError, 'Invalid token'
        when 2
          # Re-authentication request succeeds
          { 'result' => 'success', 'token' => 'refreshed_token' }
        when 3
          # Retry with new token succeeds
          { 'modules' => [] }
        else
          raise 'Unexpected request sequence'
        end
      end

      result = client.search_modules('smb')
      expect(result).to eq({ 'modules' => [] })
      expect(client.instance_variable_get(:@token)).to eq('refreshed_token')
    end

    it 'stops retrying after max_retries when API calls keep failing' do
      retry_attempt = 0

      allow(client).to receive(:send_request) do |request_array|
        if request_array[0] == 'auth.login'
          # Re-authentication succeeds
          { 'result' => 'success', 'token' => 'new_token' }
        else
          # Always raise AuthenticationError for API calls
          retry_attempt += 1
          raise Msf::MCP::Metasploit::AuthenticationError, 'Invalid token'
        end
      end

      # After exhausting retries (max_retries=2), re-raises the last error
      expect {
        client.search_modules('smb')
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError, 'Invalid token')

      # initial call + 2 retries = 3 API attempts
      expect(retry_attempt).to eq(3)
    end

    it 'does not auto-reauth if credentials not stored' do
      # Create new client without authenticating
      new_client = described_class.new(host: host, port: port)
      new_client.instance_variable_set(:@token, 'some_token')

      allow(new_client).to receive(:send_request).and_raise(Msf::MCP::Metasploit::AuthenticationError, 'Invalid token')

      expect {
        new_client.search_modules('smb')
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError, 'Invalid token')
    end

    it 'logs wlog when attempting re-authentication' do
      call_count = 0
      allow(client).to receive(:send_request) do |request_array|
        call_count += 1
        case call_count
        when 1
          raise Msf::MCP::Metasploit::AuthenticationError, 'Invalid token'
        when 2
          { 'result' => 'success', 'token' => 'new_token' }
        when 3
          { 'modules' => [] }
        end
      end

      expect(client).to receive(:wlog).with(hash_including(message: /Attempting to re-authenticate/), anything, anything)
      client.search_modules('smb')
    end

    it 'raises with descriptive message when re-authentication itself fails' do
      allow(client).to receive(:send_request) do |request_array|
        if request_array[0] == 'auth.login'
          raise Msf::MCP::Metasploit::AuthenticationError, 'Bad credentials'
        else
          raise Msf::MCP::Metasploit::AuthenticationError, 'Invalid token'
        end
      end

      expect {
        client.search_modules('smb')
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError, /Unable to authenticate after 2 attempts: Bad credentials/)
    end

    it 'resets retry count after successful re-authentication' do
      call_sequence = []

      allow(client).to receive(:send_request) do |request_array|
        if request_array[0] == 'module.search'
          if call_sequence.count { |c| c == :search_call } == 0
            call_sequence << :search_call
            # First search call fails
            raise Msf::MCP::Metasploit::AuthenticationError, 'Invalid token'
          else
            call_sequence << :search_retry
            # Retry succeeds
            { 'modules' => ['mod1'] }
          end
        elsif request_array[0] == 'auth.login'
          call_sequence << :reauth
          { 'result' => 'success', 'token' => "token#{call_sequence.length}" }
        elsif request_array[0] == 'db.hosts'
          if call_sequence.count { |c| c == :hosts_call } == 0
            call_sequence << :hosts_call
            # First hosts call fails
            raise Msf::MCP::Metasploit::AuthenticationError, 'Invalid token'
          else
            call_sequence << :hosts_retry
            # Retry succeeds
            { 'hosts' => [] }
          end
        else
          raise "Unexpected request: #{request_array[0]}"
        end
      end

      # First call with auto-reauth
      result1 = client.search_modules('smb')
      expect(result1).to eq({ 'modules' => ['mod1'] })

      # Second call with auto-reauth (retry count should have been reset)
      result2 = client.db_hosts({})
      expect(result2).to eq({ 'hosts' => [] })

      # Verify the sequence: search fail, reauth, search retry, hosts fail, reauth, hosts retry
      expect(call_sequence).to eq([:search_call, :reauth, :search_retry, :hosts_call, :reauth, :hosts_retry])
    end
  end
end
