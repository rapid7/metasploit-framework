require 'spec_helper'
require 'metasploit/framework/login_scanner/db2'

describe Metasploit::Framework::LoginScanner::DB2 do
  let(:public) { 'root' }
  let(:private) { 'toor' }
  let(:test_cred) {
    Metasploit::Framework::Credential.new( public: public, private: private )
  }
  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: true
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  context '#attempt_login' do

    context 'when the socket errors' do
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
