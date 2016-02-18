require 'spec_helper'
require 'metasploit/framework/login_scanner/manageengine_desktop_central'

RSpec.describe Metasploit::Framework::LoginScanner::ManageEngineDesktopCentral do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

    let(:session_id) do
      'DCJSESSIONID=5628CFEA339C2688D74267B03CDA88BD; '
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
      Rex::Proto::Http::Response.new(302, 'Moved Temporarily')
    end

    let(:fail_auth_response) do
      Rex::Proto::Http::Response.new(200, 'OK')
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
      context 'when target is ManageEngine Desktop Central' do
        let(:response) do
          res = Rex::Proto::Http::Response.new(200, 'OK')
          res.body = 'ManageEngine Desktop Central'
          res
        end
        it 'returns true' do
          expect(subject.check_setup).to be_truthy
        end
      end

      context 'when target is not ManageEngine Desktop Central' do
        it 'returns false' do
          expect(subject.check_setup).to be_falsey
        end
      end
    end

    describe '#get_sid' do
      context 'when there is no session ID' do
        let(:response) do
          res = Rex::Proto::Http::Response.new(200, 'OK')
          res.headers['Set-Cookie'] = session_id

          res
        end

        it 'returns a new session ID' do
          expect(subject.get_sid(response)).to include('DCJSESSIONID')
        end
      end
    end

    describe '#get_hidden_inputs' do
      let(:response) do
        html = %Q|
        <input type="hidden" name="buildNum" id="buildNum" value="90109"/>
        <input type="hidden" name="clearCacheBuildNum" id="clearCacheBuildNum" value="-1"/>
        |
        res = Rex::Proto::Http::Response.new(200, 'OK')
        res.body = html
        res
      end

      context 'when there are hidden login inputs' do
        it 'returns a Hash' do
          expect(subject.get_hidden_inputs(response)).to be_kind_of(Hash)
        end

        it 'returns the value for buildNum' do
          expect(subject.get_hidden_inputs(response)['buildNum']).to eq('90109')
        end

        it 'returns the value for clearCacheBuildNum' do
          expect(subject.get_hidden_inputs(response)['clearCacheBuildNum']).to eq('-1')
        end
      end
    end

    describe '#get_login_state' do
      context 'when the credential is valid' do
        let(:response) { successful_auth_response }
        it 'returns a hash indicating a successful login' do
          expect(subject.get_login_state(username, good_password)[:status]).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when the creential is invalid' do
        let(:response) { fail_auth_response }
        it 'returns a hash indicating an incorrect cred' do
          expect(subject.get_login_state(username, good_password)[:status]).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end
    end

    describe '#attempt_login' do
      context 'when the credential is valid' do
        let(:response) { successful_auth_response }
        let(:cred_obj) { Metasploit::Framework::Credential.new(public: username, private: good_password) }

        it 'returns a Result object indicating a successful login' do
          result = subject.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
        end

        it 'returns successful login' do
          result = subject.attempt_login(cred_obj)
          expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when the credential is invalid' do
        let(:response) { fail_auth_response }
        let(:cred_obj) { Metasploit::Framework::Credential.new(public: username, private: bad_password) }

        it 'returns a Result object' do
          result = subject.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
        end

        it 'returns incorrect credential status' do
          result = subject.attempt_login(cred_obj)
          expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end
    end
end