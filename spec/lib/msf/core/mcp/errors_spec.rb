# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Error do
  describe 'inheritance' do
    it 'inherits from StandardError' do
      expect(described_class).to be < StandardError
    end

    it 'can be rescued as StandardError' do
      expect do
        raise described_class, 'test'
      end.to raise_error(StandardError)
    end
  end
end

RSpec.describe Msf::MCP::Config::ConfigurationError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end
end

RSpec.describe Msf::MCP::Config::ValidationError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end

  describe '#initialize' do
    it 'stores validation errors' do
      errors = { 'msf_api.type' => 'must be one of the valid API types: messagepack, json-rpc' }
      exception = described_class.new(errors)
      expect(exception.errors).to eq(errors)
    end

    it 'returns a generic message if no errors have been stored' do
      exception = described_class.new
      expect(exception.message).to eq("Configuration validation failed")
    end

    it 'formats error messages correctly' do
      errors = {
        'msf_api.type' => 'must be one of the valid API types: messagepack, json-rpc',
        'msf_api.host' => 'must be a non-empty string'
      }
      exception = described_class.new(errors)
      expected_message = <<~MSG.chomp
        Configuration validation failed:
          - msf_api.type must be one of the valid API types: messagepack, json-rpc
          - msf_api.host must be a non-empty string
      MSG
      expect(exception.message).to eq(expected_message)
    end
  end
end

RSpec.describe Msf::MCP::Security::ValidationError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end
end

RSpec.describe Msf::MCP::Security::RateLimitExceededError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end

  describe '#initialize' do
    it 'stores retry_after value' do
      exception = described_class.new(32)
      expect(exception.retry_after).to eq(32)
    end

    it 'formats message correctly' do
      exception = described_class.new(32)
      expect(exception.message).to eq("Rate limit exceeded. Retry after 32 seconds.")
    end
  end
end

RSpec.describe Msf::MCP::Metasploit::AuthenticationError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end
end

RSpec.describe Msf::MCP::Metasploit::ConnectionError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end
end

RSpec.describe Msf::MCP::Metasploit::APIError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end
end

RSpec.describe Msf::MCP::Metasploit::RpcStartupError do
  describe 'inheritance' do
    it 'inherits from Msf::MCP::Error' do
      expect(described_class).to be < Msf::MCP::Error
    end
  end
end
