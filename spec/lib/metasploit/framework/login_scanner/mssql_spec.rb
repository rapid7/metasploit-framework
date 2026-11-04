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

  context '#attempt_login' do
    let(:client) { instance_double(Rex::Proto::MSSQL::Client) }

    before(:each) do
      allow(Rex::Proto::MSSQL::Client).to receive(:new).and_return(client)
    end

    context 'when there is a connection error' do
      it 'disconnects the client and returns the connection error' do
        connection_error = Rex::ConnectionError.new
        allow(client).to receive(:mssql_login).and_raise(connection_error)
        expect(client).to receive(:disconnect).once

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to be(connection_error)
      end
    end

    context 'when the login fails' do
      it 'disconnects the client' do
        allow(client).to receive(:mssql_login).and_return(false)
        expect(client).to receive(:disconnect).once

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
      end

      it 'disconnects the client when proof retention is enabled' do
        login_scanner.use_client_as_proof = true
        allow(client).to receive(:mssql_login).and_return(false)
        expect(client).to receive(:disconnect).once

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
        expect(result.proof).to be_nil
        expect(result.connection).to be_nil
      end
    end

    context 'when the login succeeds' do
      it 'disconnects the client when proof retention is disabled' do
        allow(client).to receive(:mssql_login).and_return(true)
        expect(client).to receive(:disconnect).once

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
      end

      it 'transfers the live client when proof retention is enabled' do
        socket = double('socket')
        login_scanner.use_client_as_proof = true
        allow(client).to receive(:mssql_login).and_return(true)
        allow(client).to receive(:sock).and_return(socket)
        expect(client).not_to receive(:disconnect)

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
        expect(result.proof).to be(client)
        expect(result.connection).to be(socket)
      end

      it 'disconnects the client if the result cannot take ownership' do
        result_error = StandardError.new('result construction failed')
        login_scanner.use_client_as_proof = true
        allow(client).to receive(:mssql_login).and_return(true)
        allow(client).to receive(:sock).and_return(double('socket'))
        allow(Metasploit::Framework::LoginScanner::Result).to receive(:new).and_raise(result_error)
        expect(client).to receive(:disconnect).once

        expect { login_scanner.attempt_login(pub_blank) }.to raise_error(result_error)
      end

      it 'disconnects the client if retrieving the socket fails' do
        socket_error = StandardError.new('socket unavailable')
        login_scanner.use_client_as_proof = true
        allow(client).to receive(:mssql_login).and_return(true)
        allow(client).to receive(:sock).and_raise(socket_error)
        expect(client).to receive(:disconnect).once
        expect(login_scanner).to receive(:elog).with(socket_error, error: socket_error)

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to be(socket_error)
      end
    end

    context 'when an unexpected login error occurs' do
      it 'disconnects the client and preserves the existing error result' do
        login_error = StandardError.new('login failed unexpectedly')
        allow(client).to receive(:mssql_login).and_raise(login_error)
        expect(client).to receive(:disconnect).once
        expect(login_scanner).to receive(:elog).with(login_error, error: login_error)

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to be(login_error)
      end
    end

    context 'when client construction fails' do
      it 'returns the construction error without a secondary cleanup error' do
        construction_error = StandardError.new('construction failed')
        allow(Rex::Proto::MSSQL::Client).to receive(:new).and_raise(construction_error)
        expect(login_scanner).to receive(:elog).with(construction_error, error: construction_error)

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        expect(result.proof).to be(construction_error)
      end
    end

    context 'when disconnecting the client fails' do
      it 'logs the cleanup error without replacing a failed login result' do
        cleanup_error = StandardError.new('cleanup failed')
        allow(client).to receive(:mssql_login).and_return(false)
        allow(client).to receive(:disconnect).and_raise(cleanup_error)
        expect(login_scanner).to receive(:elog).with('Failed to disconnect MSSQL client', error: cleanup_error)

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::INCORRECT
        expect(result.proof).to be_nil
      end

      it 'logs the cleanup error without downgrading a successful login' do
        cleanup_error = StandardError.new('cleanup failed')
        allow(client).to receive(:mssql_login).and_return(true)
        allow(client).to receive(:disconnect).and_raise(cleanup_error)
        expect(login_scanner).to receive(:elog).with('Failed to disconnect MSSQL client', error: cleanup_error)

        result = login_scanner.attempt_login(pub_blank)

        expect(result.status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
        expect(result.proof).to be_nil
      end

      it 'does not replace a result construction error' do
        result_error = StandardError.new('result construction failed')
        cleanup_error = StandardError.new('cleanup failed')
        login_scanner.use_client_as_proof = true
        allow(client).to receive(:mssql_login).and_return(true)
        allow(client).to receive(:sock).and_return(double('socket'))
        allow(client).to receive(:disconnect).and_raise(cleanup_error)
        allow(Metasploit::Framework::LoginScanner::Result).to receive(:new).and_raise(result_error)
        expect(login_scanner).to receive(:elog).with('Failed to disconnect MSSQL client', error: cleanup_error)

        expect { login_scanner.attempt_login(pub_blank) }.to raise_error(result_error)
      end
    end
  end
end
