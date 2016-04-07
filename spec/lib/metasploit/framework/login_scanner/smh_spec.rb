
require 'spec_helper'
require 'metasploit/framework/login_scanner/smh'

RSpec.describe Metasploit::Framework::LoginScanner::Smh do

  subject(:smh_cli) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  context "#attempt_login" do

    let(:username) { 'admin' }
    let(:password) { 'password' }

    let(:cred) do
      Metasploit::Framework::Credential.new(
        paired: true,
        public: username,
        private: password
      )
    end

    let(:invalid_cred) do
      Metasploit::Framework::Credential.new(
        paired: true,
        public: 'username',
        private: 'novalid'
      )
    end

    context "when Rex::Proto::Http::Client#connect raises Rex::ConnectionError" do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Rex::ConnectionError)
        expect(smh_cli.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context "when Rex::Proto::Http::Client#connect raises Timeout::Error" do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Timeout::Error)
        expect(smh_cli.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context "when Rex::Proto::Http::Client#connect raises EOFError" do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(EOFError)
        expect(smh_cli.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context "when valid HP System Management application" do
      before :example do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|

          if req.opts['uri'] &&
              req.opts['vars_post'] &&
              req.opts['vars_post']['user'] &&
              req.opts['vars_post']['user'] == username &&
              req.opts['vars_post']['password'] &&
              req.opts['vars_post']['password'] == password
            res = Rex::Proto::Http::Response.new(200)
            res.headers['CpqElm-Login'] = 'success'
            res
          else
            res = Rex::Proto::Http::Response.new(404)
          end

          res
        end
      end

      context "when valid login" do
        it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL' do
          expect(smh_cli.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context "when invalid login" do
        it 'returns status Metasploit::Model::Login::Status::INCORRECT' do
          expect(smh_cli.attempt_login(invalid_cred).status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end

    end
  end

end
