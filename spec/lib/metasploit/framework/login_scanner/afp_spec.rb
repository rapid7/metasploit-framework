
require 'spec_helper'
require 'metasploit/framework/login_scanner/afp'

RSpec.describe Metasploit::Framework::LoginScanner::AFP do

  subject(:scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: false, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::Tcp::Client'

  it { is_expected.to respond_to :login_timeout }

  describe "#attempt_login" do
    let(:pub_blank) do
      Metasploit::Framework::Credential.new(
        paired: true,
        public: "public",
        private: ''
      )
    end

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

    it "considers :skip_user to mean failure" do
      expect(scanner).to receive(:connect)
      expect(scanner).to receive(:login).and_return(:skip_user)
      result = scanner.attempt_login(pub_blank)

      expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
      expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
    end

  end

end

