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

  describe '#banner' do
    it 'is a public method' do
      expect(described_class.public_method_defined?(:banner)).to be true
    end
  end

  describe '#data_connect' do
    let(:control_socket) { double('control socket', peerhost: '192.0.2.1') }
    let(:data_socket) { double('data socket') }

    before do
      allow(ftp_scanner).to receive(:datasocket).and_return(nil, data_socket)
      allow(ftp_scanner).to receive(:datasocket=)
      allow(ftp_scanner).to receive(:send_cmd).with(['PASV'], true, control_socket).and_return(
        "227 Entering Passive Mode (10,0,0,50,192,0)\r\n"
      )
      allow(ftp_scanner).to receive(:framework).and_return(nil)
      allow(ftp_scanner).to receive(:framework_module).and_return(nil)
      allow(Rex::Socket::Tcp).to receive(:create).and_return(data_socket)
    end

    it 'uses the control connection host instead of the PASV advertised host' do
      expect(ftp_scanner.data_connect(nil, control_socket)).to eq(data_socket)
      expect(Rex::Socket::Tcp).to have_received(:create).with(
        'PeerHost' => '192.0.2.1',
        'PeerPort' => 49_152,
        'Context' => { 'Msf' => nil, 'MsfExploit' => nil }
      )
    end

    it 'clears an old socket and permits a retry after a malformed response' do
      old_data_socket = double('old data socket', shutdown: nil, close: nil)
      current_data_socket = old_data_socket
      allow(ftp_scanner).to receive(:datasocket) { current_data_socket }
      allow(ftp_scanner).to receive(:datasocket=) { |socket| current_data_socket = socket }
      allow(ftp_scanner).to receive(:send_cmd).with(['PASV'], true, control_socket).and_return(
        "227 Entering Passive Mode (invalid)\r\n",
        "227 Entering Passive Mode (192,0,2,1,192,0)\r\n"
      )

      expect(ftp_scanner.data_connect(nil, control_socket)).to be_nil
      expect(current_data_socket).to be_nil
      expect(ftp_scanner.data_connect(nil, control_socket)).to eq(data_socket)
      expect(old_data_socket).to have_received(:shutdown)
      expect(old_data_socket).to have_received(:close)
    end
  end

  context '#attempt_login' do
    let(:mock_socket) { double('socket') }

    before(:example) do
      ftp_scanner.host = '127.0.0.1'
      ftp_scanner.port = 21
      ftp_scanner.connection_timeout = 30
      ftp_scanner.ftp_timeout = 16
      ftp_scanner.stop_on_success = true
      ftp_scanner.cred_details = detail_group
    end

    context 'when the connection fails' do

      it 'returns UNABLE_TO_CONNECT for a Rex::ConnectionError' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise Rex::ConnectionError }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns UNABLE_TO_CONNECT for a Rex::AddressInUse' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise Rex::AddressInUse }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns UNABLE_TO_CONNECT for a ::EOFError' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise ::EOFError }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns UNABLE_TO_CONNECT for a ::Timeout::Error' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise ::Timeout::Error }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns UNABLE_TO_CONNECT for a Errno::ECONNRESET' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise Errno::ECONNRESET }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'returns UNABLE_TO_CONNECT for a Rex::ConnectionTimeout' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise Rex::ConnectionTimeout }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
      end

      it 'sets proof to the exception message' do
        expect(Rex::Socket::Tcp).to receive(:create) { raise ::Timeout::Error, 'connection timed out' }
        expect(ftp_scanner.attempt_login(pub_pri).proof).to eq 'connection timed out'
      end

    end

    context 'when the connection succeeds' do
      before(:example) do
        allow(ftp_scanner).to receive(:connect).and_return(mock_socket)
        allow(ftp_scanner).to receive(:disconnect)
      end

      context 'and the login fails' do

        it 'returns UNABLE_TO_CONNECT when send_user returns nil' do
          allow(ftp_scanner).to receive(:send_user).and_return(nil)
          expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        end

        it 'sets proof to the expected string when the response is nil' do
          allow(ftp_scanner).to receive(:send_user).and_return(nil)
          expect(ftp_scanner.attempt_login(pub_pri).proof).to eq 'No response to login command'
        end

        it 'returns INCORRECT when send_user returns a non-2xx non-331 response' do
          allow(ftp_scanner).to receive(:send_user).and_return("530 Login incorrect\r\n")
          expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::INCORRECT
        end

        it 'sets proof to the stripped server response when INCORRECT' do
          allow(ftp_scanner).to receive(:send_user).and_return("530 Login incorrect\r\n")
          expect(ftp_scanner.attempt_login(pub_pri).proof).to eq '530 Login incorrect'
        end

        it 'does not call send_pass when send_user response does not match 331 or 2xx' do
          allow(ftp_scanner).to receive(:send_user).and_return("530 Login incorrect\r\n")
          expect(ftp_scanner).not_to receive(:send_pass)
          ftp_scanner.attempt_login(pub_pri)
        end

        it 'returns INCORRECT when send_pass returns a non-2xx response' do
          allow(ftp_scanner).to receive(:send_user).and_return("331 Password required\r\n")
          allow(ftp_scanner).to receive(:send_pass).and_return("530 Login incorrect\r\n")
          expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::INCORRECT
        end

        it 'returns INCORRECT when send_user returns 2xx and send_pass returns a non-2xx response' do
          allow(ftp_scanner).to receive(:send_user).and_return("230 Login successful\r\n")
          allow(ftp_scanner).to receive(:send_pass).and_return("530 Login incorrect\r\n")
          expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::INCORRECT
        end

        it 'returns UNABLE_TO_CONNECT when send_pass returns nil' do
          allow(ftp_scanner).to receive(:send_user).and_return("331 Password required\r\n")
          allow(ftp_scanner).to receive(:send_pass).and_return(nil)
          expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        end

      end

      context 'and the login succeeds' do

        it 'returns SUCCESSFUL when send_user returns 331 and send_pass returns 2xx' do
          allow(ftp_scanner).to receive(:send_user).and_return("331 Password required\r\n")
          allow(ftp_scanner).to receive(:send_pass).and_return("230 Login successful\r\n")
          expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
        end

        it 'returns SUCCESSFUL when send_user returns 2xx and send_pass returns 2xx' do
          allow(ftp_scanner).to receive(:send_user).and_return("230 Login successful\r\n")
          allow(ftp_scanner).to receive(:send_pass).and_return("230 Already logged in\r\n")
          expect(ftp_scanner.attempt_login(pub_pri).status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
        end

        it 'sets proof to the stripped server response' do
          allow(ftp_scanner).to receive(:send_user).and_return("331 Password required\r\n")
          allow(ftp_scanner).to receive(:send_pass).and_return("230 Login successful\r\n")
          expect(ftp_scanner.attempt_login(pub_pri).proof).to eq "230 Login successful"
        end

      end

      context 'result metadata' do
        before(:example) do
          allow(ftp_scanner).to receive(:send_user).and_return("331 Password required\r\n")
          allow(ftp_scanner).to receive(:send_pass).and_return("230 Login successful\r\n")
        end

        it 'sets result.host to the scanner host' do
          expect(ftp_scanner.attempt_login(pub_pri).host).to eq '127.0.0.1'
        end

        it 'sets result.port to the scanner port' do
          expect(ftp_scanner.attempt_login(pub_pri).port).to eq 21
        end

        it 'sets result.protocol to tcp' do
          expect(ftp_scanner.attempt_login(pub_pri).protocol).to eq 'tcp'
        end

        it 'sets result.service_name to ftp' do
          expect(ftp_scanner.attempt_login(pub_pri).service_name).to eq 'ftp'
        end

      end
    end
  end

end
