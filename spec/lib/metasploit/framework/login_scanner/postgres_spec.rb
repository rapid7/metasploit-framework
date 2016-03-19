require 'spec_helper'
require 'metasploit/framework/login_scanner/postgres'

RSpec.describe Metasploit::Framework::LoginScanner::Postgres do
  let(:public) { 'root' }
  let(:private) { 'toor' }
  let(:realm) { 'template1' }

  let(:full_cred) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: private,
        realm: realm
    )
  }

  let(:cred_no_realm) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: private
    )
  }

  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: true

  context '#attempt_login' do
    context 'when the login is successful' do
      it 'returns a result object with a status of success' do
        fake_conn = double('fake_connection')

        expect(fake_conn).to receive(:close)
        expect(Msf::Db::PostgresPR::Connection).to receive(:new).and_return fake_conn
        expect(login_scanner.attempt_login(full_cred).status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
      end
    end

    context 'when there is no realm on the credential' do
      it 'uses template1 as the default realm' do
        expect(Msf::Db::PostgresPR::Connection).to receive(:new).with('template1', 'root', 'toor', 'tcp://:')
        login_scanner.attempt_login(cred_no_realm)
      end
    end

    context 'when the realm is invalid but the rest of the credential is not' do
      it 'includes the details in the result proof' do
        expect(Msf::Db::PostgresPR::Connection).to receive(:new).and_raise RuntimeError, "blah\tC3D000"
        result = login_scanner.attempt_login(cred_no_realm)
        expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
        expect(result.proof).to eq "C3D000, Creds were good but database was bad"
      end
    end

    context 'when the username or password is invalid' do
      it 'includes a message in proof, indicating why it failed' do
        expect(Msf::Db::PostgresPR::Connection).to receive(:new).and_raise RuntimeError, "blah\tC28000"
        result = login_scanner.attempt_login(cred_no_realm)
        expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
        expect(result.proof).to eq "Invalid username or password"
      end
    end

    context 'when any other type of error occurs' do
      it 'returns a failure with the error message in the proof' do
        expect(Msf::Db::PostgresPR::Connection).to receive(:new).and_raise RuntimeError, "unknown error"
        result = login_scanner.attempt_login(cred_no_realm)
        expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
        expect(result.proof).to eq "unknown error"
      end
    end
  end

end
