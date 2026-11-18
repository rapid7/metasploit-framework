require 'spec_helper'

RSpec.describe Msf::RPC::JSON::Request do
  it 'continues to accept a response with symbolized keys by default' do
    request = described_class.new(URI('http://localhost:55552/api/1.0'), method: 'core.version')
    response = nil
    request.callback { |value| response = value }

    request.__send__(:process, '{"jsonrpc":"2.0","id":1,"result":{"version":"6"}}')

    expect(response.result).to eq(version: '6')
  end

  describe 'response processing with string keys' do
    let(:request) do
      described_class.new(URI('http://localhost:55552/api/1.0'), method: 'core.version', symbolize_names: false)
    end

    it 'accepts a valid JSON-RPC response' do
      response = nil
      request.callback { |value| response = value }

      request.__send__(:process, '{"jsonrpc":"2.0","id":1,"result":{"version":"6"}}')

      expect(response).to be_a(Msf::RPC::JSON::Response)
      expect(response.id).to eq(1)
      expect(response.result).to eq('version' => '6')
    end

    it 'rejects an unsupported JSON-RPC version' do
      error = nil
      request.errback { |value| error = value }

      request.__send__(:process, '{"jsonrpc":"1.0","id":1,"result":{}}')

      expect(error).to be_a(Msf::RPC::JSON::InvalidResponse)
    end
  end
end
