require 'spec_helper'
require 'metasploit/framework/login_scanner/nessus'

RSpec.describe Metasploit::Framework::LoginScanner::Nessus do

    subject(:http_scanner) { described_class.new }

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

    let(:username) do
      'username'
    end

    let(:good_password) do
      'good_password'
    end

    let(:bad_password) do
      'bad_password'
    end

    let(:successful_auth_response) do
      res = Rex::Proto::Http::Response.new(200, 'OK')
      res.body = 'token'
      res
    end

    let(:fail_auth_response) do
      Rex::Proto::Http::Response.new(401, 'Unauthorized')
    end

    let(:response) do
      Rex::Proto::Http::Response.new(200, 'OK')
    end

    before(:example) do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(response)
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
    end

    describe '#check_setup' do
      let(:msp_html_response) do
        res = Rex::Proto::Http::Response.new(200, 'OK')
        res.body = 'Nessus'
        res
      end

      context 'when target is Nessus' do
        let(:response) { msp_html_response }
        it 'returns true' do
          expect(http_scanner.check_setup).to be_truthy
        end
      end

      context 'when target is not Nessus' do
        it 'returns false' do
          expect(http_scanner.check_setup).to be_falsey
        end
      end
    end

    describe '#get_login_state' do
      it 'sends a login request to /session' do
        allow(http_scanner).to receive(:send_request).with(hash_including('uri'=>'/session')).and_return(response)
        http_scanner.get_login_state(username, good_password)
      end

      it 'sends a login request containing the username and password' do
        expected_hash = {
          'vars_post' => {
            "username" => username,
            "password" => good_password
          }
        }
        allow(http_scanner).to receive(:send_request).with(hash_including(expected_hash)).and_return(response)
        http_scanner.get_login_state(username, good_password)
      end

      context 'when the credential is valid' do
        let(:response) { successful_auth_response }
        it 'returns a hash indicating a successful login' do
          successful_status = Metasploit::Model::Login::Status::SUCCESSFUL
          expect(http_scanner.get_login_state(username, good_password)[:status]).to eq(successful_status)
        end
      end

      context 'when the creential is invalid' do
        let(:response) { fail_auth_response }
        it 'returns a hash indicating an incorrect cred' do
          incorrect_status = Metasploit::Model::Login::Status::INCORRECT
          expect(http_scanner.get_login_state(username, good_password)[:status]).to eq(incorrect_status)
        end
      end
    end

    describe '#attempt_login' do
      context 'when the credential is valid' do
        let(:response) { successful_auth_response }

        it 'returns a Result object indicating a successful login' do
          cred_obj = Metasploit::Framework::Credential.new(public: username, private: good_password)
          result = http_scanner.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when the credential is invalid' do
        let(:response) { fail_auth_response }
        it 'returns a Result object indicating an incorrect cred' do
          cred_obj = Metasploit::Framework::Credential.new(public: username, private: bad_password)
          result = http_scanner.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end
    end
end
