# -*- coding:binary -*-
require 'rex/proto/nuuo/response'

RSpec.describe Rex::Proto::Nuuo::Response do
  subject(:response) {described_class.new}
  let(:header) {'Header'}
  let(:hvalue) {'Value'}
  let(:body) {'test'}
  let(:data) {"NUCM/1.0 200\r\n#{header}:#{hvalue}\r\nContent-Length:4\r\n\r\n#{body}"}

  describe '#parse' do
    it 'returns a ParseCode' do
      expect(response.parse(data)).to eq(Rex::Proto::Nuuo::Response::ParseCode::Completed)
    end

    it 'sets the headers' do
      response.parse(data)
      expect(response.headers[header]).to eq(hvalue)
    end

    it 'sets the body' do
      response.parse(data)
      expect(response.body).to eq(body)
    end
  end
end
