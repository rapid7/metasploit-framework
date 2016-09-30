require 'spec_helper'
require 'metasploit/framework/login_scanner/mysql'

RSpec.describe Metasploit::Framework::LoginScanner::MySQL do
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

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: false, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  context '#attempt_login' do

    context 'when the attempt is successful' do
      it 'returns a result object with a status of Metasploit::Model::Login::Status::SUCCESSFUL' do
        expect(::RbMysql).to receive(:connect).and_return "fake mysql handle"
        expect(login_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
      end
    end

    context 'when the attempt is unsuccessful' do
      context 'due to connection refused' do
        it 'returns a result with a status of Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
          expect(::RbMysql).to receive(:connect).and_raise Errno::ECONNREFUSED
          expect(login_scanner.attempt_login(pub_pub).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        end

        it 'returns a result with the proof containing an appropriate error message' do
          expect(::RbMysql).to receive(:connect).and_raise Errno::ECONNREFUSED
          expect(login_scanner.attempt_login(pub_pub).proof).to be_a(Errno::ECONNREFUSED)
        end
      end

      context 'due to connection timeout' do
        it 'returns a result with a status of Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
          expect(::RbMysql).to receive(:connect).and_raise RbMysql::ClientError
          expect(login_scanner.attempt_login(pub_pub).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        end

        it 'returns a result with the proof containing an appropriate error message' do
          expect(::RbMysql).to receive(:connect).and_raise RbMysql::ClientError
          expect(login_scanner.attempt_login(pub_pub).proof).to be_a(RbMysql::ClientError)
        end
      end

      context 'due to operation timeout' do
        it 'returns a result with a status of Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
          expect(::RbMysql).to receive(:connect).and_raise Errno::ETIMEDOUT
          expect(login_scanner.attempt_login(pub_pub).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        end

        it 'returns a result with the proof containing an appropriate error message' do
          expect(::RbMysql).to receive(:connect).and_raise Errno::ETIMEDOUT
          expect(login_scanner.attempt_login(pub_pub).proof).to be_a(Errno::ETIMEDOUT)
        end
      end

      context 'due to not being allowed to connect from this host' do
        it 'returns a result with a status of Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
          expect(::RbMysql).to receive(:connect).and_raise RbMysql::HostNotPrivileged, "Host not privileged"
          expect(login_scanner.attempt_login(pub_pub).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        end

        it 'returns a result with the proof containing an appropriate error message' do
          expect(::RbMysql).to receive(:connect).and_raise RbMysql::HostNotPrivileged, "Host not privileged"
          expect(login_scanner.attempt_login(pub_pub).proof).to be_a(RbMysql::HostNotPrivileged)
        end
      end

      context 'due to access denied' do
        it 'returns a result with a status of Metasploit::Model::Login::Status::INCORRECT' do
          expect(::RbMysql).to receive(:connect).and_raise RbMysql::AccessDeniedError, "Access Denied"
          expect(login_scanner.attempt_login(pub_pub).status).to eq Metasploit::Model::Login::Status::INCORRECT
        end

        it 'returns a result with the proof containing an appropriate error message' do
          expect(::RbMysql).to receive(:connect).and_raise RbMysql::AccessDeniedError, "Access Denied"
          expect(login_scanner.attempt_login(pub_pub).proof).to be_a(RbMysql::AccessDeniedError)
        end
      end
    end
  end

end
