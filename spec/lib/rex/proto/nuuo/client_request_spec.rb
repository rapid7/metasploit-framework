# -*- coding:binary -*-
require 'rex/proto/nuuo/client_request'

RSpec.describe Rex::Proto::Nuuo::ClientRequest do
  subject(:client_request) {
    opts = {
      'user_session' => user_session,
      'headers' => headers_hash,
      'data' => data
    }
    described_class.new(opts)
  }
  let(:user_session) {nil}
  let(:headers_hash) {{}}
  let(:data) {nil}

  describe '#to_s' do
    context 'given no additional options' do
      it 'returns a USERLOGIN request' do
        expect(client_request.to_s).to eq("USERLOGIN NUCM/1.0\r\n\r\n")
      end
    end

    context 'given a headers hash' do
      let(:headers_hash) {{
        'TestHeader' => 'TestValue',
        'TestHeader1' => 'TestValue1'
      }}
      it 'dumps the headers after the method line' do
        expect(client_request.to_s).to eq("USERLOGIN NUCM/1.0\r\nTestHeader: TestValue\r\nTestHeader1: TestValue1\r\n\r\n")
      end
    end

    context 'given a user_session and User-Session-No header' do
      let(:user_session) {'0'}
      let(:headers_hash) {{'User-Session-No' => '1'}}

      it 'prefers the User-Session-No in the headers hash' do
        expect(client_request.to_s).to eq("USERLOGIN NUCM/1.0\r\nUser-Session-No: 1\r\n\r\n")
      end
    end
  end

  describe '#set_method' do
    it 'returns the method variable' do
      expect(client_request.set_method).to eq('USERLOGIN')
    end
  end

  describe '#set_proto_version' do
    it 'returns the protocol and version separated by /' do
      expect(client_request.set_proto_version).to eq("NUCM/1.0\r\n")
    end
  end


  describe '#set_header' do

    context 'given no user session number' do
      let(:user_session) {nil}

      it 'returns an empty header' do
        expect(client_request.set_header('user_session', 'User-Session-No')).to eq('')
      end
    end

    context 'given user session number' do
      let(:user_session) {'987'}

      it 'returns a User-Session-No header' do
        expect(client_request.set_header('user_session', 'User-Session-No')).to eq("User-Session-No: 987\r\n")
      end
    end

    context 'given a nonexistent key' do
      it 'returns an empty header' do
        expect(client_request.set_header('DoesNotExist', 'DoesNotExist')).to eq('')
      end
    end

    context 'given a key specified in the headers hash' do
      let(:user_session) {'987'}
      let(:headers_hash) {{'User-Session-No' => '1000'}}

      it 'returns an empty header' do
        expect(client_request.set_header('user_session', 'User-Session-No')).to eq('')
      end
    end

  end

  describe '#set_extra_headers' do
    context 'given an empty headers hash' do
      it 'returns an empty string' do
        expect(client_request.set_extra_headers).to eq('')
      end
    end

    context 'given a headers hash' do
      let(:headers_hash) {{
        'Header' => 'Value',
        'Another' => 'One'
      }}

      it 'returns formatted headers' do
        expect(client_request.set_extra_headers).to eq("Header: Value\r\nAnother: One\r\n")
      end
    end
  end

  describe '#set_body' do
    context 'given an empty body variable' do
      it 'returns \r\n' do
        expect(client_request.set_body).to eq("\r\n")
      end
    end

    context 'given body content' do
      let(:data) {"test data"}

      it 'returns \r\n followed by the body content' do
        expect(client_request.set_body).to eq("\r\ntest data")
      end
    end
  end

  describe '#set_formatted_header' do
    let(:name) {'HeaderName'}
    let(:value) {'HeaderValue'}

    it 'creates a request header' do
      expect(subject.set_formatted_header(name, value)).to eq("HeaderName: HeaderValue\r\n")
    end
  end
end
