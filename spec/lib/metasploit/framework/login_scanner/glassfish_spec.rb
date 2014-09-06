
require 'spec_helper'
require 'metasploit/framework/login_scanner/glassfish'

describe Metasploit::Framework::LoginScanner::Glassfish do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  subject(:http_scanner) { described_class.new }

  context 'Instance Methods' do
    let(:good_version) do
      '4.0'
    end

    let(:bad_version) do
      'Unknown'
    end

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

    let(:res_code) do
      200
    end

    before do
      http_scanner.version = good_version
    end

    context '#send_request' do
      let(:req_opts) do
        {'uri'=>'/', 'method'=>'GET'}
      end

      it 'returns a Rex::Proto::Http::Response object' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new(res_code))
        expect(http_scanner.send_request(req_opts)).to be_kind_of(Rex::Proto::Http::Response)
      end
    end

    context '#is_secure_admin_disabled?' do
      it 'returns true when Secure Admin is disabled' do
        res = Rex::Proto::Http::Response.new(res_code)
        res.stub(:body).and_return('Secure Admin must be enabled')
        expect(http_scanner.is_secure_admin_disabled?(res)).to eq(true)
      end

      it 'returns false when Secure Admin is enabled' do
        res = Rex::Proto::Http::Response.new(res_code)
        res.stub(:body).and_return('')
        http_scanner.is_secure_admin_disabled?(res).should eq(false)
      end
    end

    context '#try_login' do
      it 'sends a login request to /j_security_check' do
        http_scanner.should_receive(:send_request).with(hash_including('uri'=>'/j_security_check'))
        http_scanner.try_login(cred)
      end

      it 'sends a login request containing the username and password' do
        http_scanner.should_receive(:send_request).with(hash_including('data'=>"j_username=#{username}&j_password=#{password}&loginButton=Login"))
        http_scanner.try_login(cred)
      end
    end

    context '#try_glassfish_2' do
      it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL for a valid credential' do
        good_auth_res = Rex::Proto::Http::Response.new(302)
        good_res = Rex::Proto::Http::Response.new(200)
        good_res.stub(:body).and_return('<title>Deploy Enterprise Applications/Modules</title>')
        http_scanner.should_receive(:try_login).with(cred).and_return(good_auth_res)
        http_scanner.should_receive(:send_request).with(kind_of(Hash)).and_return(good_res)
        http_scanner.try_glassfish_2(cred)[:status].should eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end

      it 'returns Metasploit::Model::Login::Status::INCORRECT for an invalid credential' do
        bad_auth_res = Rex::Proto::Http::Response.new(200)
        http_scanner.should_receive(:try_login).with(cred).and_return(bad_auth_res)
        http_scanner.try_glassfish_2(cred)[:status].should eq(Metasploit::Model::Login::Status::INCORRECT)
      end
    end

    context '#try_glassfish_3' do
      it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL for a valid credential' do
        good_auth_res = Rex::Proto::Http::Response.new(302)
        good_res = Rex::Proto::Http::Response.new(200)
        good_res.stub(:body).and_return('<title>Deploy Applications or Modules</title>')
        http_scanner.should_receive(:try_login).with(cred).and_return(good_auth_res)
        http_scanner.should_receive(:send_request).with(kind_of(Hash)).and_return(good_res)
        http_scanner.try_glassfish_3(cred)[:status].should eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end

      it 'returns status Metasploit::Model::Login::Status::SUCCESSFUL based on a disabled remote admin message' do
        good_auth_res = Rex::Proto::Http::Response.new(200)
        good_auth_res.stub(:body).and_return('Secure Admin must be enabled')
        http_scanner.should_receive(:try_login).with(cred).and_return(good_auth_res)
        http_scanner.try_glassfish_3(cred)[:status].should eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end

      it 'returns status Metasploit::Model::Login::Status::INCORRECT for an invalid credential' do
        bad_auth_res = Rex::Proto::Http::Response.new(200)
        http_scanner.should_receive(:try_login).with(cred).and_return(bad_auth_res)
        http_scanner.try_glassfish_3(cred)[:status].should eq(Metasploit::Model::Login::Status::INCORRECT)
      end
    end

    context '#attempt_login' do
      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Rex::ConnectionError)

        expect(http_scanner.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end

      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Timeout::Error)

        expect(http_scanner.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end

      it 'returns status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(EOFError)

        expect(http_scanner.attempt_login(cred).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
      end

      it 'raises a GlassfishError exception due to an unsupported Glassfish version' do
        http_scanner.version = bad_version
        expect { http_scanner.attempt_login(cred) }.to raise_exception(Metasploit::Framework::LoginScanner::GlassfishError)
      end
    end

  end


end

