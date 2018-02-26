require 'spec_helper'
require 'metasploit/framework/login_scanner/smb'

RSpec.describe Metasploit::Framework::LoginScanner::SMB do
  let(:public) { 'root' }
  let(:private) { 'toor' }

  let(:pub_blank) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: ''
    )
  }

  let(:pub_pub) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: public
    )
  }

  let(:pub_pri) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: private
    )
  }


  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: true
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::Tcp::Client'


  context '#attempt_login' do
    context 'when it cannot connect to the server' do
      it 'returns a result with an UNABLE_TO_CONNECT status' do
        expect(login_scanner).to receive(:connect).and_raise Rex::ConnectionError
        expect(login_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end
    end

    context 'when it can connect' do
      before(:each) do
        allow(login_scanner).to receive(:connect)
        login_scanner.dispatcher = RubySMB::Dispatcher::Socket.new(StringIO.new)
        allow_any_instance_of(RubySMB::Client).to receive(:tree_connect)
      end

      let(:success) { WindowsError::NTStatus::STATUS_SUCCESS }
      let(:locked) { WindowsError::NTStatus::STATUS_ACCOUNT_LOCKED_OUT }
      let(:fail) { WindowsError::NTStatus::STATUS_LOGON_FAILURE }

      it 'returns a result with SUCCESSFUL status if it succeeds' do
        expect_any_instance_of(RubySMB::Client).to receive(:login).and_return(success)
        expect(login_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
      end

      it 'returns a result with LOCKED_OUT status if the account is locked' do
        expect_any_instance_of(RubySMB::Client).to receive(:login).and_return(locked)
        expect(login_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::LOCKED_OUT
      end

      it 'returns a result with INCORRECT status if it fails' do
        expect_any_instance_of(RubySMB::Client).to receive(:login).and_return(fail)
        expect(login_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::INCORRECT
      end

      it 'returns the result with the credential the result is for' do
        expect_any_instance_of(RubySMB::Client).to receive(:login).and_return(success)
        expect(login_scanner.attempt_login(pub_pri).credential).to eq pub_pri
      end

      it 'returns the result with the protocol set to tcp' do
        expect_any_instance_of(RubySMB::Client).to receive(:login).and_return(success)
        expect(login_scanner.attempt_login(pub_pri).protocol).to eq 'tcp'
      end

      it 'returns the result with the  service_name set to smb' do
        expect_any_instance_of(RubySMB::Client).to receive(:login).and_return(success)
        expect(login_scanner.attempt_login(pub_pri).service_name).to eq 'smb'
      end
    end
  end

end

