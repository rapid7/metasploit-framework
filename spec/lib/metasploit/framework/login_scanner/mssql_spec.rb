require 'spec_helper'
require 'metasploit/framework/login_scanner/mssql'

RSpec.describe Metasploit::Framework::LoginScanner::MSSQL do
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
  it_behaves_like 'Metasploit::Framework::LoginScanner::NTLM'
  it_behaves_like 'Metasploit::Framework::Tcp::Client'

  it { is_expected.to respond_to :windows_authentication }

  before(:each) do
    creds = double('Metasploit::Framework::CredentialCollection')
    allow(creds).to receive(:pass_file)
    allow(creds).to receive(:username)
    allow(creds).to receive(:password)
    allow(creds).to receive(:user_file)
    allow(creds).to receive(:userpass_file)
    allow(creds).to receive(:prepended_creds).and_return([])
    allow(creds).to receive(:additional_privates).and_return([])
    allow(creds).to receive(:additional_publics).and_return([])
    allow(creds).to receive(:empty?).and_return(true)
    login_scanner.cred_details = creds
  end

  context 'validations' do
    context '#windows_authentication' do
      it 'is not valid for the string true' do
        login_scanner.windows_authentication = 'true'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:windows_authentication]).to include 'is not included in the list'
      end

      it 'is not valid for the string false' do
        login_scanner.windows_authentication = 'false'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:windows_authentication]).to include 'is not included in the list'
      end

      it 'is  valid for true class' do
        login_scanner.windows_authentication = true
        expect(login_scanner.errors[:windows_authentication]).to be_empty
      end

      it 'is  valid for false class' do
        login_scanner.windows_authentication = false
        expect(login_scanner.errors[:windows_authentication]).to be_empty
      end
    end
  end

  context '#attempt_login' do
    context 'when the is a connection error' do
      it 'returns a result with the connection_error status' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:mssql_login).and_raise ::Rex::ConnectionError
        expect(my_scanner.attempt_login(pub_blank).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end
    end

    context 'when the login fails' do
      it 'returns a result object with a status of Metasploit::Model::Login::Status::INCORRECT' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:mssql_login).and_return false
        expect(my_scanner.attempt_login(pub_blank).status).to eq Metasploit::Model::Login::Status::INCORRECT
      end
    end

    context 'when the login succeeds' do
      it 'returns a result object with a status of Metasploit::Model::Login::Status::SUCCESSFUL' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:mssql_login).and_return true
        expect(my_scanner.attempt_login(pub_blank).status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
      end
    end
  end

end
