require 'spec_helper'
require 'metasploit/framework/login_scanner/swg'

describe Metasploit::Framework::LoginScanner::SymantecWebGateway do

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

    def mock_http_cli(res)
      cli = Rex::Proto::Http::Client
      allow(cli).to receive(:request_cgi).with(any_args)
      allow(cli).to receive(:send_recv).with(any_args).and_return(res)
      allow(cli).to receive(:set_config).with(any_args)
      allow(cli).to receive(:close)
      allow(cli).to receive(:connect)
      allow(Rex::Proto::Http::Client).to receive(:new).and_return(cli)
    end

    describe '#check_setup' do
      let(:swg_html_response) do
        res = Rex::Proto::Http::Response.new(200, 'OK')
        res.body = 'Symantec Web Gateway'
        res
      end

      let(:empty_html_response) do
        Rex::Proto::Http::Response.new(200, 'OK')
      end

      context 'when target is Symantec Web Gateway' do
        it 'returns true' do
          mock_http_cli(swg_html_response)
          expect(subject.check_setup).to be_truthy
        end
      end

      context 'when target is not Symantec Web Gateway' do
        it 'returns false' do
          mock_http_cli(empty_html_response)
          expect(subject.check_setup).to be_falsey
        end
      end
    end

    describe '#send_request' do
      context 'when a valid request is sent' do
        it 'returns a response object' do
          expected_response = Rex::Proto::Http::Response.new(200, 'OK')
          mock_http_cli(expected_response)
          expect(subject.send_request({'uri'=>'/'})).to be_kind_of(Rex::Proto::Http::Response)
        end
      end
    end

    describe '#get_last_sid' do
      context 'when there is no session ID' do
        it 'returns a new session ID' do
          res = Rex::Proto::Http::Response.new(200, 'OK')
          res.headers['Set-Cookie'] = session_id
          mock_http_cli(res)
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
        it 'returns a hash indicating a successful login' do
          mock_http_cli(successful_auth_response)
          successful_status = Metasploit::Model::Login::Status::SUCCESSFUL
          expect(subject.get_login_state(username, good_password)[:status]).to eq(successful_status)
        end
      end

      context 'when the creential is invalid' do
        it 'returns a hash indicating an incorrect cred' do
          mock_http_cli(fail_auth_response)
          incorrect_status = Metasploit::Model::Login::Status::INCORRECT
          expect(subject.get_login_state(username, good_password)[:status]).to eq(incorrect_status)
        end
      end
    end

    describe '#attempt_login' do
      context 'when the credential is valid' do
        it 'returns a Result object indicating a successful login' do
          cred_obj = Metasploit::Framework::Credential.new(public: username, private: good_password)
          mock_http_cli(successful_auth_response)
          result = subject.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when the credential is invalid' do
        it 'returns a Result object indicating an incorrect cred' do
          cred_obj = Metasploit::Framework::Credential.new(public: username, private: bad_password)
          mock_http_cli(fail_auth_response)
          result = subject.attempt_login(cred_obj)
          expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end
    end
end