require 'spec_helper'
require 'metasploit/framework/login_scanner/vnc'

describe Metasploit::Framework::LoginScanner::VNC do
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


  context '#attempt_login' do
    it 'creates a new RFB client' do
      Rex::Proto::RFB::Client.should_receive(:new).and_call_original
      login_scanner.attempt_login(test_cred)
    end

    it 'returns a connection_error result when the handshake fails' do
      Rex::Proto::RFB::Client.any_instance.should_receive(:handshake).and_return false
      result = login_scanner.attempt_login(test_cred)
      expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
    end

    it 'returns a failed result when authentication fails' do
      Rex::Proto::RFB::Client.any_instance.should_receive(:handshake).and_return true
      Rex::Proto::RFB::Client.any_instance.should_receive(:authenticate).with(private).and_return false
      result = login_scanner.attempt_login(test_cred)
      expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
    end

    context 'when the socket errors' do
      it 'returns a connection_error result for an EOFError' do
        my_scanner = login_scanner
        my_scanner.should_receive(:connect).and_raise ::EOFError
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::EOFError.new.to_s
      end

      it 'returns a connection_error result for an Rex::AddressInUse' do
        my_scanner = login_scanner
        my_scanner.should_receive(:connect).and_raise ::Rex::AddressInUse
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Rex::AddressInUse.new.to_s
      end

      it 'returns a connection_error result for an Rex::ConnectionError' do
        my_scanner = login_scanner
        my_scanner.should_receive(:connect).and_raise ::Rex::ConnectionError
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Rex::ConnectionError.new.to_s
      end

      it 'returns a connection_error result for an Rex::ConnectionTimeout' do
        my_scanner = login_scanner
        my_scanner.should_receive(:connect).and_raise ::Rex::ConnectionTimeout
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Rex::ConnectionTimeout.new.to_s
      end

      it 'returns a connection_error result for an ::Timeout::Error' do
        my_scanner = login_scanner
        my_scanner.should_receive(:connect).and_raise ::Timeout::Error
        result = my_scanner.attempt_login(test_cred)
        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to eq ::Timeout::Error.new.to_s
      end
    end



  end

end