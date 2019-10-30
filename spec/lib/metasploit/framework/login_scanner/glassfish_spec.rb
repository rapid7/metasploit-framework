
require 'spec_helper'
require 'metasploit/framework/login_scanner/glassfish'

RSpec.describe Metasploit::Framework::LoginScanner::Glassfish do

  subject(:http_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'


  let(:good_version) do
    '4.0'
  end

  let(:bad_version) do
    'Unknown'
  end

  let(:username) do
    'admin'
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

    it 'parses JSESSIONID session cookies' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new(res_code))
      allow_any_instance_of(Rex::Proto::Http::Response).to receive(:get_cookies).and_return("JSESSIONID=JSESSIONID_MAGIC_VALUE;")
      http_scanner.send_request(req_opts)
      expect(http_scanner.jsession).to eq("JSESSIONID_MAGIC_VALUE")
    end
  end

  context '#is_secure_admin_disabled?' do
    it 'returns true when Secure Admin is disabled' do
      res = Rex::Proto::Http::Response.new(res_code)
      allow(res).to receive(:body).and_return('Secure Admin must be enabled')

      expect(http_scanner.is_secure_admin_disabled?(res)).to be_truthy
    end

    it 'returns false when Secure Admin is enabled' do
      res = Rex::Proto::Http::Response.new(res_code)
      allow(res).to receive(:body).and_return('')

      expect(http_scanner.is_secure_admin_disabled?(res)).to be_falsey
    end
  end

  context '#try_login' do
    it 'sends a login request to /j_security_check' do
      expect(http_scanner).to receive(:send_request).with(hash_including('uri'=>'/j_security_check'))
      http_scanner.try_login(cred)
    end

    it 'sends a login request containing the username and password' do
      expect(http_scanner).to receive(:send_request).with(hash_including('data'=>"j_username=#{username}&j_password=#{password}&loginButton=Login"))
      http_scanner.try_login(cred)
    end
  end

  context '#try_glassfish_2' do

    let(:login_ok_message) do
      '<title>Deploy Enterprise Applications/Modules</title>'
    end

    before :example do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|
        if req.opts['uri'] && req.opts['uri'].include?('j_security_check') &&
            req.opts['data'] &&
            req.opts['data'].include?("j_username=#{username}") &&
            req. opts['data'].include?("j_password=#{password}")
          res = Rex::Proto::Http::Response.new(302)
          res.headers['Location'] = '/applications/upload.jsf'
          res.headers['Set-Cookie'] = 'JSESSIONID=GOODSESSIONID'
          res
        elsif req.opts['uri'] && req.opts['uri'].include?('j_security_check')
          res = Rex::Proto::Http::Response.new(200)
          res.body = 'bad login'
        elsif req.opts['uri'] &&
            req.opts['uri'].include?('/applications/upload.jsf')
          res = Rex::Proto::Http::Response.new(200)
          res.body = '<title>Deploy Enterprise Applications/Modules</title>'
        else
          res = Rex::Proto::Http::Response.new(404)
        end

        res
      end
    end

    it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL for a valid credential' do
      expect(http_scanner.try_glassfish_2(cred)[:status]).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    it 'returns Metasploit::Model::Login::Status::INCORRECT for an invalid credential' do
      expect(http_scanner.try_glassfish_2(bad_cred)[:status]).to eq(Metasploit::Model::Login::Status::INCORRECT)
    end
  end

  context '#try_glassfish_3' do

    let(:login_ok_message) do
      '<title>Deploy Enterprise Applications/Modules</title>'
    end

    before :example do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|
        if req.opts['uri'] && req.opts['uri'].include?('j_security_check') &&
            req.opts['data'] &&
            req.opts['data'].include?("j_username=#{username}") &&
            req. opts['data'].include?("j_password=#{password}")
          res = Rex::Proto::Http::Response.new(302)
          res.headers['Location'] = '/common/applications/uploadFrame.jsf'
          res.headers['Set-Cookie'] = 'JSESSIONID=GOODSESSIONID'
          res
        elsif req.opts['uri'] && req.opts['uri'].include?('j_security_check') &&
            req.opts['data'] &&
            req.opts['data'].include?("j_username=#{username_disabled}") &&
            req. opts['data'].include?("j_password=#{password_disabled}")
          res = Rex::Proto::Http::Response.new(200)
          res.body = 'Secure Admin must be enabled'
        elsif req.opts['uri'] && req.opts['uri'].include?('j_security_check')
          res = Rex::Proto::Http::Response.new(200)
          res.body = 'bad login'
        elsif req.opts['uri'] &&
            req.opts['uri'].include?('/common/applications/uploadFrame.jsf')
          res = Rex::Proto::Http::Response.new(200)
          res.body = '<title>Deploy Applications or Modules'
        else
          res = Rex::Proto::Http::Response.new(404)
        end

        res
      end
    end

    it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL for a valid credential' do
      expect(http_scanner.try_glassfish_3(cred)[:status]).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL based on a disabled remote admin message' do
      expect(http_scanner.try_glassfish_3(disabled_cred)[:status]).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    it 'returns status Metasploit::Model::Login::Status::INCORRECT for an invalid credential' do
      expect(http_scanner.try_glassfish_3(bad_cred)[:status]).to eq(Metasploit::Model::Login::Status::INCORRECT)
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

    context 'when Glassfish version 2' do
      let(:login_ok_message) do
        '<title>Deploy Enterprise Applications/Modules</title>'
      end

      it 'returns a Metasploit::Framework::LoginScanner::Result' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|
          if req.opts['uri'] && req.opts['uri'].include?('j_security_check') &&
              req.opts['data'] &&
              req.opts['data'].include?("j_username=#{username}") &&
              req. opts['data'].include?("j_password=#{password}")
            res = Rex::Proto::Http::Response.new(302)
            res.headers['Location'] = '/applications/upload.jsf'
            res.headers['Set-Cookie'] = 'JSESSIONID=GOODSESSIONID'
            res
          elsif req.opts['uri'] && req.opts['uri'].include?('j_security_check')
            res = Rex::Proto::Http::Response.new(200)
            res.body = 'bad login'
          elsif req.opts['uri'] &&
              req.opts['uri'].include?('/applications/upload.jsf')
            res = Rex::Proto::Http::Response.new(200)
            res.body = '<title>Deploy Enterprise Applications/Modules</title>'
          else
            res = Rex::Proto::Http::Response.new(404)
          end

          res
        end

        expect(http_scanner.attempt_login(cred)).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
      end
    end

    context 'when Glassfish version 3' do
      let(:login_ok_message) do
        '<title>Deploy Enterprise Applications/Modules</title>'
      end


      it 'returns a Metasploit::Framework::LoginScanner::Result' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv) do |cli, req|
          if req.opts['uri'] && req.opts['uri'].include?('j_security_check') &&
              req.opts['data'] &&
              req.opts['data'].include?("j_username=#{username}") &&
              req. opts['data'].include?("j_password=#{password}")
            res = Rex::Proto::Http::Response.new(302)
            res.headers['Location'] = '/common/applications/uploadFrame.jsf'
            res.headers['Set-Cookie'] = 'JSESSIONID=GOODSESSIONID'
            res
          elsif req.opts['uri'] && req.opts['uri'].include?('j_security_check') &&
              req.opts['data'] &&
              req.opts['data'].include?("j_username=#{username_disabled}") &&
              req. opts['data'].include?("j_password=#{password_disabled}")
            res = Rex::Proto::Http::Response.new(200)
            res.body = 'Secure Admin must be enabled'
          elsif req.opts['uri'] && req.opts['uri'].include?('j_security_check')
            res = Rex::Proto::Http::Response.new(200)
            res.body = 'bad login'
          elsif req.opts['uri'] &&
              req.opts['uri'].include?('/common/applications/uploadFrame.jsf')
            res = Rex::Proto::Http::Response.new(200)
            res.body = '<title>Deploy Applications or Modules'
          else
            res = Rex::Proto::Http::Response.new(404)
          end

          res
        end

        expect(http_scanner.attempt_login(cred)).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
      end
    end
  end

  context '#extract_version' do
    # Thanks to shodan for Server headers
    subject(:extracted_version) { http_scanner.extract_version(server_header) }

    context 'with 9.1 header' do
      let(:server_header) { "Sun Java System Application Server 9.1_02" }
      it { is_expected.to start_with("9") }
    end

    context 'with 4.0 header' do
      let(:server_header) { "GlassFish Server Open Source Edition  4.0" }
      it { is_expected.to start_with("4") }
    end

    context 'with 3.0 header' do
      let(:server_header) { "GlassFish Server Open Source Edition 3.0.1" }
      it { is_expected.to start_with("3") }
    end

    context 'with non-open-source header' do
      let(:server_header) { "Oracle GlassFish Server 3.1.2.3" }
      it { is_expected.to start_with("3") }
    end

    context 'with 2.1 header' do
      let(:server_header) { "Sun GlassFish Enterprise Server v2.1" }
      it { is_expected.to start_with("2") }
    end

    context 'with bogus header' do
      let(:server_header) { "Apache-Coyote/1.1" }
      it { is_expected.to be_nil }
    end


  end

end

