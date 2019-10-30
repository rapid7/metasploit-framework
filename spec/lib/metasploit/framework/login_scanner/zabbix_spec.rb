
require 'spec_helper'
require 'metasploit/framework/login_scanner/zabbix'

RSpec.describe Metasploit::Framework::LoginScanner::Zabbix do

  subject(:http_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'


  let(:good_version) do
    '2.4.1'
  end

  let(:bad_version) do
    'Unknown'
  end

  let(:username) do
    'Admin'
  end

  let(:username_disabled) do
    'admin_disabled'
  end

  let(:password) do
    'password'
  end

  let(:password_disabled) do
    'password_disabled'
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

  before do
    http_scanner.instance_variable_set(:@version, good_version)
  end

  context '#send_request' do
    let(:req_opts) do
      {'uri'=>'/', 'method'=>'GET'}
    end

    it 'returns a Rex::Proto::Http::Response object' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new(res_code))
      expect(http_scanner.send_request(req_opts)).to be_kind_of(Rex::Proto::Http::Response)
    end

    it 'parses zbx_sessionid session cookies' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new(res_code))
      allow_any_instance_of(Rex::Proto::Http::Response).to receive(:get_cookies).and_return("zbx_sessionid=ZBXSESSIONID_MAGIC_VALUE;")
      http_scanner.send_request(req_opts)
      expect(http_scanner.zsession).to eq("ZBXSESSIONID_MAGIC_VALUE")
    end
  end

  context '#try_credential' do
    it 'sends a login request to /index.php' do
      expect(http_scanner).to receive(:send_request).with(hash_including('uri'=>'/index.php'))
      http_scanner.try_credential(cred)
    end

    it 'sends a login request containing the username and password' do
      expect(http_scanner).to receive(:send_request).with(hash_including('data'=>"request=&name=#{username}&password=#{password}&autologin=1&enter=Sign%20in"))
      http_scanner.try_credential(cred)
    end
  end

  context '#try_login' do

    let(:login_ok_message) do
      '<title>Zabbix 2.4 Appliance: User profile</title>'
    end

    before :example do
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
          res.body = '<title>Zabbix 2.4 Appliance: User profile</title>'
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

    context 'when Zabbix' do
      let(:login_ok_message) do
        '<title>Zabbix 2.4 Appliance: User profile</title>'
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
            res.body = '<title>Zabbix 2.4 Appliance: User profile</title>'
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

