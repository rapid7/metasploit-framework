require 'spec_helper'

RSpec.describe Rex::Proto::MSSQL::Client do
  context '#parse_prelogin_response' do
    let(:buf) { "\x00\x00\x15\x00\x06\x01\x00\e\x00\x01\x02\x00\x1C\x00\x01\x03\x00\x1D\x00\x00\xFF\x10\x00\x03\xE8\x00\x00\x02\x00" }
    let(:client) { Rex::Proto::MSSQL::Client.allocate }

    it 'correctly parses a prelogin response' do
      result = client.parse_prelogin_response(buf)
      expect(result).to eq({ version: '16.0.1000', encryption: 2 })
    end
  end
end
