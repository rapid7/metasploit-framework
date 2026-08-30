
require 'spec_helper'
require 'metasploit/framework/login_scanner/chef_webui'

RSpec.describe Metasploit::Framework::LoginScanner::ChefWebUI do

  subject(:http_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'


  let(:username) do
    'admin'
  end

  let(:password) do
    'password'
  end

  let(:cred) do
    Metasploit::Framework::Credential.new(
      paired: true,
      public: username,
      private: password
    )
  end

  let(:bad_cred) do
    Metasploit::Framework::Credential.new(
      paired: true,
      public: 'bad',
      private: 'bad'
    )
  end

  let(:disabled_cred) do
    Metasploit::Framework::Credential.new(
        paired: true,
        public: username_disabled,
        private: password_disabled
    )
  end

  let(:res_code) do
    200
  end

  context '#send_request' do
    let(:req_opts) do
      {'uri'=>'/users/sign_in', 'method'=>'GET'}
    end

    it 'returns a Rex::Proto::Http::Response object' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new(res_code))
      expect(http_scanner.send_request(req_opts)).to be_kind_of(Rex::Proto::Http::Response)
    end

    it 'parses session cookies' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new(res_code))
      allow_any_instance_of(Rex::Proto::Http::Response).to receive(:get_cookies).and_return("_sandbox_session=c2g2ZXVhZWRpU1RMTDg1SmkyS0pQVnUwYUFCcDZJYklwb2gyYmhZd2dvcGI3b2VSaWd6L0Q4SkVOaytKa1VPNmd0R01HRHFabnFZZ09YUVZhVHFPWnhRdkZTSHF6VnpCU1Y3VFRRcTEyV0xVTUtLNlZIK3VBM3V2ZlFTS2FaOWV3cjlPT2RLRlZIeG1UTElMY3ozUEtIOFNzWkFDbW9VQ1VpRlF6ZThiNXZHbmVudWY0Nk9PSSsxSFg2WVZjeklvLS1UTk1GU2x6QXJFR3lFSjNZL0JhYzBRPT0%3D--6f0cc3051739c8a95551339c3f2a084e0c30924e")
      http_scanner.send_request(req_opts)
      expect(http_scanner.session_name).to eq("_sandbox_session")
      expect(http_scanner.session_id).to eq("c2g2ZXVhZWRpU1RMTDg1SmkyS0pQVnUwYUFCcDZJYklwb2gyYmhZd2dvcGI3b2VSaWd6L0Q4SkVOaytKa1VPNmd0R01HRHFabnFZZ09YUVZhVHFPWnhRdkZTSHF6VnpCU1Y3VFRRcTEyV0xVTUtLNlZIK3VBM3V2ZlFTS2FaOWV3cjlPT2RLRlZIeG1UTElMY3ozUEtIOFNzWkFDbW9VQ1VpRlF6ZThiNXZHbmVudWY0Nk9PSSsxSFg2WVZjeklvLS1UTk1GU2x6QXJFR3lFSjNZL0JhYzBRPT0%3D--6f0cc3051739c8a95551339c3f2a084e0c30924e")
    end
  end

  context '#try_credential' do
    it 'sends a login request to /users/login_exec' do
      expect(http_scanner).to receive(:send_request).with(hash_including('uri'=>'/users/login_exec'))
      http_scanner.try_credential('byV12YkMA6NV3zJFqclZjy1JR+AZYbCx75gT0dipoAo=', cred)
    end

    it 'sends a login request containing the username and password' do
      expect(http_scanner).to receive(:send_request).with(hash_including('data'=>"utf8=%E2%9C%93&authenticity_token=byV12YkMA6NV3zJFqclZjy1JR%2bAZYbCx75gT0dipoAo%3d&name=#{username}&password=#{password}&commit=login"))
      http_scanner.try_credential('byV12YkMA6NV3zJFqclZjy1JR+AZYbCx75gT0dipoAo=', cred)
    end
  end

  context '#try_login' do

    let(:login_ok_message) do
      'New password for the User'
    end

    before :example do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|
        if req.opts['uri'] && req.opts['uri'].include?('/users/login_exec') &&
            req.opts['data'] &&
            req.opts['data'].include?("name=#{username}") &&
            req.opts['data'].include?("password=#{password}")
          res = Rex::Proto::Http::Response.new(302)
          res.headers['Location'] = "/users/#{username}/edit"
          res.headers['Set-Cookie'] = '_sandbox_session=c2g2ZXVhZWRpU1RMTDg1SmkyS0pQVnUwYUFCcDZJYklwb2gyYmhZd2dvcGI3b2VSaWd6L0Q4SkVOaytKa1VPNmd0R01HRHFabnFZZ09YUVZhVHFPWnhRdkZTSHF6VnpCU1Y3VFRRcTEyV0xVTUtLNlZIK3VBM3V2ZlFTS2FaOWV3cjlPT2RLRlZIeG1UTElMY3ozUEtIOFNzWkFDbW9VQ1VpRlF6ZThiNXZHbmVudWY0Nk9PSSsxSFg2WVZjeklvLS1UTk1GU2x6QXJFR3lFSjNZL0JhYzBRPT0%3D--6f0cc3051739c8a95551339c3f2a084e0c30924e'
          res
        elsif req.opts['uri'] && req.opts['uri'].include?('/users/login')
          res = Rex::Proto::Http::Response.new(200)
          res.body = '<input name="authenticity_token" type="hidden" value="byV12YkMA6NV3zJFqclZjy1JR+AZYbCx75gT0dipoAo=" />'
        elsif req.opts['uri'] && req.opts['uri'].include?('/users/login_exec')
          res = Rex::Proto::Http::Response.new(200)
          res.body = 'bad login'
        elsif req.opts['uri'] &&
            req.opts['uri'].include?("/users/#{username}/edit")
          res = Rex::Proto::Http::Response.new(200)
          res.body = 'New password for the User'
        else
          res = Rex::Proto::Http::Response.new(404)
        end

        res
      end
    end

    it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL for a valid credential' do
      expect(http_scanner.try_login(cred)[:status]).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    it 'returns Metasploit::Model::Login::Status::INCORRECT for an invalid credential' do
      expect(http_scanner.try_login(bad_cred)[:status]).to eq(Metasploit::Model::Login::Status::INCORRECT)
    end
  end

  context '#attempt_login' do
    context 'when Rex::Proto::Http::Client#connect raises a Rex::ConnectionError' do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Rex::ConnectionError)
        expect(http_scanner.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context 'when Rex::Proto::Http::Client#connect raises a Timeout::Error' do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Timeout::Error)
        expect(http_scanner.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context 'when Rex::Proto::Http::Client#connect raises a EOFError' do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(EOFError)
        expect(http_scanner.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end
    end

    context 'when ChefWebUI' do
      let(:login_ok_message) do
        '<title>ChefWebUI 2.4 Appliance: User profile</title>'
      end

      it 'returns a Metasploit::Framework::LoginScanner::Result' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|
          if req.opts['uri'] && req.opts['uri'].include?('index.php') &&
              req.opts['data'] &&
              req.opts['data'].include?("name=#{username}") &&
              req. opts['data'].include?("password=#{password}")
            res = Rex::Proto::Http::Response.new(302)
            res.headers['Location'] = 'profile.php'
            res.headers['Set-Cookie'] = 'zbx_sessionid=GOODSESSIONID'
            res
          elsif req.opts['uri'] && req.opts['uri'].include?('index.php')
            res = Rex::Proto::Http::Response.new(200)
            res.body = 'bad login'
          elsif req.opts['uri'] &&
              req.opts['uri'].include?('profile.php')
            res = Rex::Proto::Http::Response.new(200)
            res.body = 'New password for the User'
          else
            res = Rex::Proto::Http::Response.new(404)
          end

          res
        end

        expect(http_scanner.attempt_login(cred)).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
      end

    end

  end

end

