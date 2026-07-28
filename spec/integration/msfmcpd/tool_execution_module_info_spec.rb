# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'

RSpec.describe 'Tool Execution End-to-End - Module Info' do
  before(:all) do
    WebMock.disable_net_connect!(allow_localhost: false)
  end

  after(:all) do
    WebMock.allow_net_connect!
  end

  let(:host) { 'localhost' }
  let(:port) { 55553 }
  let(:endpoint) { '/api/' }
  let(:api_url) { "https://#{host}:#{port}#{endpoint}" }
  let(:user) { 'test_user' }
  let(:password) { 'test_password' }

  let(:limiter) { Msf::MCP::Security::RateLimiter.new(requests_per_minute: 60, burst_size: 10) }
  let(:client) do
    c = Msf::MCP::Metasploit::MessagePackClient.new(host: host, port: port, endpoint: endpoint)
    c.authenticate(user, password)
    c
  end
  let(:server_context) { { msf_client: client, rate_limiter: limiter } }

  before do
    stub_request(:post, api_url)
      .with(body: ['auth.login', user, password].to_msgpack)
      .to_return(
        status: 200,
        body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
        headers: { 'Content-Type' => 'binary/message-pack' }
      )
  end

  describe 'Module Info Integration with HTTP' do
    it 'retrieves module info through complete HTTP request flow' do
      info_stub = stub_request(:post, api_url)
        .with(body: ['module.info', 'test_token', 'exploit', 'windows/smb/ms17_010_eternalblue'].to_msgpack)
        .to_return(
          status: 200,
          body: {
            'type' => 'exploit',
            'name' => 'MS17-010 EternalBlue',
            'fullname' => 'exploit/windows/smb/ms17_010_eternalblue',
            'rank' => 'excellent',
            'disclosuredate' => '2017-03-14',
            'description' => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
            'license' => 'MSF_LICENSE',
            'filepath' => '/opt/metasploit-framework/modules/exploits/windows/smb/ms17_010_eternalblue.rb',
            'arch' => ['x64', 'x86'],
            'platform' => ['windows'],
            'authors' => ['Author1', 'Author2'],
            'privileged' => true,
            'check' => true,
            'references' => [['CVE', '2017-0144'], ['URL', 'https://example.com']],
            'targets' => { 0 => 'Windows 7', 1 => 'Windows 8' },
            'default_target' => 0,
            'options' => { 'RHOSTS' => { 'type' => 'address', 'required' => true } }
          }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      result = Msf::MCP::Tools::ModuleInfo.call(
        type: 'exploit',
        name: 'windows/smb/ms17_010_eternalblue',
        server_context: server_context
      )

      expect(info_stub).to have_been_requested.once

      expect(result).to be_a(MCP::Tool::Response)
      expect(result.error?).to be false

      data = result.structured_content[:data]
      expect(data[:fullname]).to eq('exploit/windows/smb/ms17_010_eternalblue')
      expect(data[:rank]).to eq('excellent')
      expect(data[:architectures]).to eq(['x64', 'x86'])
      expect(data[:has_check_method]).to be true

      # Verify filepath is stripped of install path
      expect(data[:filepath]).to eq('modules/exploits/windows/smb/ms17_010_eternalblue.rb')
      expect(data[:filepath]).not_to include('/opt/metasploit-framework/')

      # Verify references are transformed
      expect(data[:references]).to eq([
        { type: 'CVE', value: '2017-0144' },
        { type: 'URL', value: 'https://example.com' }
      ])

      # Verify metadata
      expect(result.structured_content[:metadata][:query_time]).to be_a(Float)
    end

    it 'handles module not found through HTTP' do
      stub_request(:post, api_url)
        .with(body: ['module.info', 'test_token', 'exploit', 'nonexistent/module'].to_msgpack)
        .to_return(
          status: 500,
          body: { 'error_message' => 'Module not found' }.to_msgpack
        )

      result = Msf::MCP::Tools::ModuleInfo.call(
        type: 'exploit',
        name: 'nonexistent/module',
        server_context: server_context
      )

      expect(result.error?).to be true
      expect(result.content.first[:text]).to include('Metasploit API error')
    end

    it 'validates module type before making HTTP request' do
      result = Msf::MCP::Tools::ModuleInfo.call(
        type: 'invalid_type',
        name: 'windows/smb/ms17_010_eternalblue',
        server_context: server_context
      )

      expect(result.error?).to be true
      expect(result.content.first[:text]).to include('Module type')
    end
  end
end
