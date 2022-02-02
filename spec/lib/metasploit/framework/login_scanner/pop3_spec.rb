require 'spec_helper'
require 'metasploit/framework/login_scanner/pop3'

RSpec.describe Metasploit::Framework::LoginScanner::POP3 do
  subject(:scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: false, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::Tcp::Client'

  context "#attempt_login" do

    let(:pub_blank) do
      Metasploit::Framework::Credential.new(
        paired: true,
        public: "public",
        private: ''
      )
    end
    context "Raised Exceptions" do
      it "Rex::ConnectionError should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT" do
        expect(scanner).to receive(:connect).and_raise(Rex::ConnectionError)
        result = scanner.attempt_login(pub_blank)

        expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end

      it "Timeout::Error should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT" do
        expect(scanner).to receive(:connect).and_raise(Timeout::Error)
        result = scanner.attempt_login(pub_blank)

        expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end

      it "EOFError should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT" do
        expect(scanner).to receive(:connect).and_raise(EOFError)
        result = scanner.attempt_login(pub_blank)

        expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context "Open Connection" do
      let(:sock) {double('socket')}

      before(:example) do
        allow(sock).to receive(:shutdown)
        allow(sock).to receive(:close)
        allow(sock).to receive(:closed?)

        allow(scanner).to receive(:sock).and_return(sock)

        expect(scanner).to receive(:connect)
        expect(scanner).to receive(:select).with([sock],nil,nil,0.4)
      end

      it "Server returns +OK" do
        expect(sock).to receive(:get_once).exactly(3).times.and_return("+OK")
        expect(sock).to receive(:put).with("USER public\r\n").once.ordered
        expect(sock).to receive(:put).with("PASS \r\n").once.ordered

        result = scanner.attempt_login(pub_blank)

        expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)

      end

      it "Server Returns Something Else" do
        allow(sock).to receive(:get_once).and_return("+ERROR")

        result = scanner.attempt_login(pub_blank)

        expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        expect(result.proof).to eq("+ERROR")

      end
    end

  end
end
