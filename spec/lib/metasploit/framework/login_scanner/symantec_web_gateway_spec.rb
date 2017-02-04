require 'spec_helper'
require 'metasploit/framework/login_scanner/symantec_web_gateway'

RSpec.describe Metasploit::Framework::LoginScanner::SymantecWebGateway do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

    let(:session_id) do
      'PHPSESSID=FAKESESSIONID;'
    end

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
      res.headers['Location'] = 'executive_summary.php'
      res.headers['Set-Cookie'] = 'PHPSESSID=NEWSESSIONID;'
      res
    end

    let(:fail_auth_response) do
      res = Rex::Proto::Http::Response.new(200, 'OK')
      res.headers['Set-Cookie'] = 'PHPSESSID=NEWSESSIONID;'
      res
    end

    subject do
      described_class.new
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
      let(:swg_html_response) do
        res = Rex::Proto::Http::Response.new(200, 'OK')
        res.body = 'Symantec Web Gateway'
        res
      end

      context 'when target is Symantec Web Gateway' do
        let(:response) { swg_html_response }
        it 'returns true' do
          expect(subject.check_setup).to be_truthy
        end
      end

      context 'when target is not Symantec Web Gateway' do
        it 'returns false' do
          expect(subject.check_setup).to be_falsey
        end
      end
    end

    describe '#get_last_sid' do
      let(:response) do
        res = Rex::Proto::Http::Response.new(200, 'OK')
        res.headers['Set-Cookie'] = session_id

        res
      end

      context 'when there is no session ID' do
        it 'returns a new session ID' do
          expect(subject.get_last_sid).to include('PHPSESSID')
        end
      end

      context 'when there is already a session ID' do
        it 'returns the current session ID' do
          # Prepend like there's already one
          subject.instance_variable_set(:@last_sid, 'PHPSESSID=PRESETSID;')
          expect(subject.get_last_sid).to include('PRESETSID')
        end
      end
    end

    describe '#get_login_state' do
      context 'when the credential is valid' do
        let(:response) { successful_auth_response }
        it 'returns a hash indicating a successful login' do
          successful_status = Metasploit::Model::Login::Status::SUCCESSFUL
          expect(subject.get_login_state(username, good_password)[:status]).to eq(successful_status)
        end
      end

      context 'when the creential is invalid' do
        let(:response) { fail_auth_response }
        it 'returns a hash indicating an incorrect cred' do
          incorrect_status = Metasploit::Model::Login::Status::INCORRECT
          expect(subject.get_login_state(username, good_password)[:status]).to eq(incorrect_status)
        end
      end
    end

    describe '#attempt_login' do
      context 'when the credential is valid' do
        let(:response) { successful_auth_response }

        it 'returns a Result object indicating a successful login' do
          cred_obj = Metasploit::Framework::Credential.new(public: username, private: good_password)
          result = subject.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when the credential is invalid' do
        let(:response) { fail_auth_response }
        it 'returns a Result object indicating an incorrect cred' do
          cred_obj = Metasploit::Framework::Credential.new(public: username, private: bad_password)
          result = subject.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end
    end
end