require 'metasploit/framework/login_scanner/bavision_cameras'

RSpec.describe Metasploit::Framework::LoginScanner::BavisionCameras do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

    subject do
      described_class.new
    end

    describe '#digest_auth' do
      let(:username) { 'admin' }
      let(:password) { '123456' }
      let(:response) {
        {
          "www-authenticate" => "Digest realm=\"IPCamera Login\", nonce=\"918fee7e0b1126e4c2577911901a181b\", qop=\"auth\""
        } 
      }

      context 'when a credential is given' do
        it 'returns a string with username' do
          expect(subject.digest_auth(username, password, response)).to include('username=')
        end

        it 'returns a string with realm' do
          expect(subject.digest_auth(username, password, response)).to include('realm=')
        end

        it 'returns a string with qop' do
          expect(subject.digest_auth(username, password, response)).to include('qop=')
        end

        it 'returns a string with uri' do
          expect(subject.digest_auth(username, password, response)).to include('uri=')
        end

        it 'returns a string with nonce' do
          expect(subject.digest_auth(username, password, response)).to include('nonce=')
        end

        it 'returns a string with nonce count' do
          expect(subject.digest_auth(username, password, response)).to include('nc=')
        end

        it 'returns a string with cnonce' do
          expect(subject.digest_auth(username, password, response)).to include('cnonce=')
        end

        it 'returns a string with response' do
          expect(subject.digest_auth(username, password, response)).to include('response=')
        end
      end
    end
end
