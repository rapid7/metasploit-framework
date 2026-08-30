require 'spec_helper'
require 'metasploit/framework/login_scanner/vmauthd'

RSpec.describe Metasploit::Framework::LoginScanner::VMAUTHD do
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

  end
end
