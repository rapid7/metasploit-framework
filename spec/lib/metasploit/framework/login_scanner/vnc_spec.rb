require 'spec_helper'
require 'metasploit/framework/login_scanner/vnc'

RSpec.describe Metasploit::Framework::LoginScanner::VNC do
  let(:private) { 'password' }
  let(:blank) { '' }
  let(:test_cred) {
    Metasploit::Framework::Credential.new( paired: false, private: private )
  }
  let(:blank_cred) {
    Metasploit::Framework::Credential.new( paired: false, private: blank )
  }
  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: false, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::Tcp::Client'


  context '#attempt_login' do
    it 'creates a new RFB client' do
      expect(Rex::Proto::RFB::Client).to receive(:new).and_call_original
      login_scanner.attempt_login(test_cred)
    end

    it 'returns a connection_error result when the handshake fails' do
      expect_any_instance_of(Rex::Proto::RFB::Client).to receive(:handshake).and_return false
      result = login_scanner.attempt_login(test_cred)
      expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
    end

    it 'returns a failed result when authentication fails' do
      expect_any_instance_of(Rex::Proto::RFB::Client).to receive(:handshake).and_return true
      expect_any_instance_of(Rex::Proto::RFB::Client).to receive(:negotiate_authentication).and_return Rex::Proto::RFB::AuthType::VNC
      expect_any_instance_of(Rex::Proto::RFB::Client).to receive(:authenticate_with_type).with(Rex::Proto::RFB::AuthType::VNC,nil,private).and_return false
      result = login_scanner.attempt_login(test_cred)
      expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
    end

    context 'when the socket errors' do
      it 'returns a connection_error result for an EOFError' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:connect).and_raise ::EOFError
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::EOFError.new.to_s
      end

      it 'returns a connection_error result for an Rex::AddressInUse' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:connect).and_raise ::Rex::AddressInUse
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Rex::AddressInUse.new.to_s
      end

      it 'returns a connection_error result for an Rex::ConnectionError' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:connect).and_raise ::Rex::ConnectionError
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Rex::ConnectionError.new.to_s
      end

      it 'returns a connection_error result for an Rex::ConnectionTimeout' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:connect).and_raise ::Rex::ConnectionTimeout
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Rex::ConnectionTimeout.new.to_s
      end

      it 'returns a connection_error result for an ::Timeout::Error' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:connect).and_raise ::Timeout::Error
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Timeout::Error.new.to_s
      end
    end



  end

end
