require 'spec_helper'
require 'metasploit/framework/login_scanner/ftp'

RSpec.describe Metasploit::Framework::LoginScanner::FTP do
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

  let(:invalid_detail) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: nil,
        private: nil
    )
  }

  let(:detail_group) {
    [ pub_blank, pub_pub, pub_pri]
  }

  subject(:ftp_scanner) {
    described_class.new
  }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: false, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::Tcp::Client'

  before(:each) do
    creds = double('Metasploit::Framework::CredentialCollection')
    allow(creds).to receive(:pass_file)
    allow(creds).to receive(:username)
    allow(creds).to receive(:user_file)
    allow(creds).to receive(:password)
    allow(creds).to receive(:userpass_file)
    allow(creds).to receive(:prepended_creds).and_return([])
    allow(creds).to receive(:additional_privates).and_return([])
    allow(creds).to receive(:additional_publics).and_return([])
    allow(creds).to receive(:empty?).and_return(true)
    ftp_scanner.cred_details = creds
  end


  context 'validations' do
    context 'ftp_timeout' do

      it 'defaults to 16' do
        expect(ftp_scanner.ftp_timeout).to eq 16
      end

      it 'is not valid for a non-number' do
        ftp_scanner.ftp_timeout = "a"
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:ftp_timeout]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        ftp_scanner.ftp_timeout = 5.76
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:ftp_timeout]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        ftp_scanner.ftp_timeout = -8
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:ftp_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        ftp_scanner.ftp_timeout = 0
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:ftp_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is valid for a legitimate  number' do
        ftp_scanner.ftp_timeout = rand(1000) + 1
        expect(ftp_scanner.errors[:ftp_timeout]).to be_empty
      end
    end


  end

  context '#attempt_login' do
    before(:example) do
      ftp_scanner.host = '127.0.0.1'
      ftp_scanner.port = 21
      ftp_scanner.connection_timeout = 30
      ftp_scanner.ftp_timeout = 16
      ftp_scanner.stop_on_success = true
      ftp_scanner.cred_details = detail_group
    end


    context 'when it fails' do

      it 'returns Metasploit::Model::Login::Status::UNABLE_TO_CONNECT for a Rex::ConnectionError' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise Rex::ConnectionError }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns Metasploit::Model::Login::Status::UNABLE_TO_CONNECT for a Rex::AddressInUse' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise Rex::AddressInUse }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns :connection_disconnect for a ::EOFError' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise ::EOFError }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns :connection_disconnect for a ::Timeout::Error' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise ::Timeout::Error }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

    end

    context 'when it succeeds' do


    end
  end

end
