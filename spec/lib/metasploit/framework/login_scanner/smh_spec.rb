
require 'spec_helper'
require 'metasploit/framework/login_scanner/smh'

describe Metasploit::Framework::LoginScanner::Smh do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  subject(:smh_cli) { described_class.new }

  context "#attempt_login" do
    let(:cred) do
      Metasploit::Framework::Credential.new(
        paired: true,
        public: 'admin',
        private: 'password'
      )
    end

    it 'Rex::ConnectionError should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Rex::ConnectionError)
      expect(smh_cli.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
    end

    it 'Timeout::Error should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Timeout::Error)

      expect(smh_cli.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
    end

    it 'EOFError should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(EOFError)

      expect(smh_cli.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
    end

  end

end
