require 'spec_helper'
require 'metasploit/framework/login_scanner/ipboard'

RSpec.describe Metasploit::Framework::LoginScanner::IPBoard do

  subject { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

  context "#attempt_login" do

    let(:username) { 'admin' }
    let(:password) { 'password' }
    let(:server_nonce) { 'nonce' }

    let(:creds) do
      Metasploit::Framework::Credential.new(
          paired: true,
          public: username,
          private: password
      )
    end

    let(:invalid_creds) do
      Metasploit::Framework::Credential.new(
          paired: true,
          public: 'username',
          private: 'novalid'
      )
    end

    context "when Rex::Proto::Http::Client#connect raises Rex::ConnectionError" do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Rex::ConnectionError)
        expect(subject.attempt_login(creds).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context "when Rex::Proto::Http::Client#connect raises Timeout::Error" do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Timeout::Error)
        expect(subject.attempt_login(creds).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context "when Rex::Proto::Http::Client#connect raises EOFError" do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(EOFError)
        expect(subject.attempt_login(creds).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context "when invalid IPBoard application" do
      let(:not_found_warning) { 'Server nonce not present, potentially not an IP Board install or bad URI.' }
      before :example do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|
          Rex::Proto::Http::Response.new(200)
        end
      end

      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        expect(subject.attempt_login(creds).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end

      it 'returns proof warning about nonce not found' do
        expect(subject.attempt_login(creds).proof).to eq(not_found_warning)
      end
    end

    context "when valid IPBoard application" do
      before :example do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|

          if req.opts['uri'] && req.opts['uri'].include?('index.php') &&
              req.opts['vars_get'] &&
              req.opts['vars_get']['app'] &&
              req.opts['vars_get']['app'] == 'core' &&
              req.opts['vars_get']['module'] &&
              req.opts['vars_get']['module'] == 'global' &&
              req.opts['vars_get']['section'] &&
              req.opts['vars_get']['section'] == 'login' &&
              req.opts['vars_get']['do'] &&
              req.opts['vars_get']['do'] == 'process' &&
              req.opts['vars_post'] &&
              req.opts['vars_post']['auth_key'] &&
              req.opts['vars_post']['auth_key'] == server_nonce &&
              req.opts['vars_post']['ips_username'] &&
              req.opts['vars_post']['ips_username'] == username &&
              req.opts['vars_post']['ips_password'] &&
              req.opts['vars_post']['ips_password'] == password
            res = Rex::Proto::Http::Response.new(200)
            res.headers['Set-Cookie'] = 'ipsconnect=ipsconnect_value;Path=/;,coppa=coppa_value;Path=/;'
          elsif req.opts['uri'] && req.opts['uri'].include?('index.php') && req.opts['method'] == 'POST'
            res = Rex::Proto::Http::Response.new(404)
          else
            res = Rex::Proto::Http::Response.new(200)
            res.body = "name='auth_key' value='#{server_nonce}'"
          end

          res
        end
      end

      context "when valid login" do
        it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL' do
          expect(subject.attempt_login(creds).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context "when invalid login" do
        it 'returns status Metasploit::Model::Login::Status::INCORRECT' do
          expect(subject.attempt_login(invalid_creds).status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end

    end
  end


end
