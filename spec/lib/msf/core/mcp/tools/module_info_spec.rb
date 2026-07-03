# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::ModuleInfo do
  let(:msf_client) { double('Msf::MCP::Metasploit::Client') }
  let(:rate_limiter) { double('Msf::MCP::Security::RateLimiter') }
  let(:server_context) do
    {
      msf_client: msf_client,
      rate_limiter: rate_limiter,
      config: {}
    }
  end

  let(:msf_response) do
    {
      'name' => 'ms17_010_eternalblue',
      'fullname' => 'exploit/windows/smb/ms17_010_eternalblue',
      'type' => 'exploit',
      'rank' => 'excellent',
      'description' => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
      'license' => 'Metasploit Framework License (BSD)',
      'filepath' => '/usr/share/metasploit-framework/modules/exploits/windows/smb/ms17_010_eternalblue.rb',
      'arch' => ['x86', 'x64'],
      'platform' => ['Windows'],
      'authors' => ['sleepya', 'zerosum0x0'],
      'references' => [
        ['CVE', '2017-0143'],
        ['MSB', 'MS17-010']
      ]
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:module_info).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_module_info')
    end
  end

  describe 'Input Schema Validation' do
    it 'defines type and name as required parameters' do
      input_schema = described_class.input_schema
      expect(input_schema.schema[:required]).to include("type", "name")
    end

    it 'defines type as enum with valid module types' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:type][:type]).to eq('string')
      expect(properties[:type][:enum]).to include('exploit', 'auxiliary', 'post', 'payload')
    end

    it 'defines name as string type' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:name][:type]).to eq('string')
    end
  end

  describe 'Output Schema' do
    it 'returns complete module details' do
      output_schema = described_class.output_schema.schema
      data_properties = output_schema[:properties][:data][:properties]

      expect(data_properties[:type]).to eq({ type: 'string' })
      expect(data_properties[:name]).to eq({ type: 'string' })
      expect(data_properties[:fullname]).to eq({ type: 'string' })
      expect(data_properties[:description]).to eq({ type: 'string' })
      expect(data_properties[:rank]).to eq({ type: 'string' })
      expect(data_properties[:authors]).to eq({ type: 'array', items: { type: 'string' } })
      expect(data_properties[:platforms]).to eq({ type: 'array', items: { type: 'string' } })
      expect(data_properties[:architectures]).to eq({ type: 'array', items: { type: 'string', enum: %w[
        x86 x86_64 x64 mips mipsle mipsbe mips64 mips64le ppc ppce500v2
        ppc64 ppc64le cbea cbea64 sparc sparc64 armle armbe aarch64 cmd
        php tty java ruby dalvik python nodejs firefox zarch r
        riscv32be riscv32le riscv64be riscv64le loongarch64
      ] } })
    end

    it 'includes options object with configuration parameters' do
      data_properties = described_class.output_schema.schema[:properties][:data][:properties]
      expect(data_properties[:options]).to eq({ type: 'object' })
      expect(data_properties[:default_options]).to eq({ type: 'object' })
    end

    it 'includes targets object for exploit modules' do
      data_properties = described_class.output_schema.schema[:properties][:data][:properties]
      expect(data_properties[:targets]).to eq({ type: 'object' })
      expect(data_properties[:default_target]).to eq({ type: 'integer' })
    end

    it 'includes references array with CVE, MSB, URL refs' do
      data_properties = described_class.output_schema.schema[:properties][:data][:properties]
      expect(data_properties[:references]).to eq({ type: 'array', items: { type: ['string', 'object'] } })
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('module_info')
    end

    it 'calls Metasploit client with module type and name' do
      described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)
      expect(msf_client).to have_received(:module_info).with('exploit', 'windows/smb/ms17_010_eternalblue')
    end

    it 'returns MCP::Tool::Response' do
      result = described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)
      expect(result).to be_a(MCP::Tool::Response)
    end

    it 'includes metadata in response' do
      result = described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:query_time]).to be_a(Float)
    end

    it 'includes transformed data in response' do
      result = described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)

      data = result.structured_content[:data]
      expect(data).to be_a(Hash)
      expect(data[:fullname]).to eq('exploit/windows/smb/ms17_010_eternalblue')
      expect(data[:type]).to eq('exploit')
    end

    it 'validates module type' do
      result = described_class.call(type: 'invalid', name: 'test', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/type/i)
    end

    it 'validates module name' do
      result = described_class.call(type: 'exploit', name: '', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/name/i)
    end

    it 'returns error response for authentication errors' do
      allow(msf_client).to receive(:module_info).and_raise(
        Msf::MCP::Metasploit::AuthenticationError.new('Invalid token')
      )

      result = described_class.call(type: 'exploit', name: 'test', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Authentication failed/)
    end

    it 'returns error response for API errors' do
      allow(msf_client).to receive(:module_info).and_raise(
        Msf::MCP::Metasploit::APIError.new('Server error')
      )

      result = described_class.call(type: 'exploit', name: 'test', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end

    it 'returns error response for rate limit exceeded' do
      allow(rate_limiter).to receive(:check_rate_limit!)
        .and_raise(Msf::MCP::Security::RateLimitExceededError.new(60))

      result = described_class.call(type: 'exploit', name: 'test', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)
    end
  end
end
