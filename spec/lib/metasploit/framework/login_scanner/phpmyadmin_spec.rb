require 'spec_helper'
require 'metasploit/framework/login_scanner/phpmyadmin'

RSpec.describe Metasploit::Framework::LoginScanner::PhpMyAdmin do
  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  subject do
    described_class.new
  end

  let(:username) do
    'username'
  end

  let(:password) do
    'password'
  end

  let(:bad_password) do
    'bad_password'
  end

  let(:response) do
    Rex::Proto::Http::Response.new(200, 'OK')
  end

  let(:successful_res) do
    res = Rex::Proto::Http::Response.new(302, 'OK')
    res.headers['Location'] = 'index.php'
    res.headers['Set-Cookie'] = 'phpMyAdmin=e6d3qlut3i67uuab10m1n6sj4b; phpMyAdmin=e6d3qlut3i67uuab10m1n6sj4b; pma_lang=en; phpMyAdmin=7e1hg9scaugr23p8c6ki8gotbd;' 
    res.body = "phpMyAdmin=e6d3qlut3i67uuab10m1n6sj4b; name=\"token\" value=\"4_0'xIB=m@&z%m%#\""
    res
  end

  let(:failed_res) do
    res = Rex::Proto::Http::Response.new(200, 'OK')
    res.headers['Set-Cookie'] = 'phpMyAdmin=e6d3qlut3i67uuab10m1n6sj4b; phpMyAdmin=e6d3qlut3i67uuab10m1n6sj4b; pma_lang=en; phpMyAdmin=7e1hg9scaugr23p8c6ki8gotbd;' 
    res.body = "phpMyAdmin=e6d3qlut3i67uuab10m1n6sj4b; name=\"token\" value=\"4_0'xIB=m@&z%m%#\""
    res
  end

  before(:each) do
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(response)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
  end

  describe '#check_setup' do
    let(:phpMyAdmin_res) do
      res = Rex::Proto::Http::Response.new(200, 'OK')
      res.body = '<h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1> PMA_VERSION:"4.8.2"'
      res
    end

    let(:phpMyAdmin_no_vers) do
      res = Rex::Proto::Http::Response.new(200, 'OK')
      res.body = '<h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1>'
      res
    end

    context 'when the target is not PhpMyAdmin' do
      it 'should return false' do
        expect(subject.check_setup).to eql(false)
      end
    end

    context 'when the version of PhpMyAdmin is detected' do
      let(:response) { phpMyAdmin_res }
      it 'should return the version' do
        expect(subject.check_setup).to eql("4.8.2")
      end
    end

    context 'when the version of PhpMyAdmin is not detected' do
      let(:response) { phpMyAdmin_no_vers }
      it 'should return "Not Detected"' do
        expect(subject.check_setup).to eql("Not Detected")
      end
    end
  end

  describe '#get_session_info' do
    context 'when session info cannot be obtained' do
      it 'should return an unable to connect status' do
        expect(subject.get_session_info).to eql({ status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Cannot retrieve session info' })
      end
    end

    context 'when session info is retrieved' do
      let(:response) { successful_res }
      it 'should return an array of the info' do
        expect(subject.get_session_info).to eql(['e6d3qlut3i67uuab10m1n6sj4b', '4_0\'xIB=m@&z%m%#', 'pma_lang=en; phpMyAdmin=7e1hg9scaugr23p8c6ki8gotbd;'])
      end
    end

    context 'when an array is returned' do
      let(:response) { successful_res }
      it 'should not be an empty array' do
        expect(subject.get_session_info.empty?).not_to eql(true)
      end
    end
  end

  describe '#do_login' do
    context 'when a successful login is made' do
      let(:response) { successful_res }
      it 'should return a successful login status' do
        expect(subject.do_login(username, password)).to eql({ :status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => response.to_s })
      end
    end

    context 'when a login is unsuccessful' do
      let(:response) { failed_res }
      it 'should return an incorrect login status' do
        expect(subject.do_login(username, password)).to eql({ :status => Metasploit::Model::Login::Status::INCORRECT, :proof => response.to_s })
      end
    end
  end

  describe '#attempt_login' do
    context 'when valid credentials are entered' do
      let(:response) { successful_res }
      it 'should return a valid credential object' do
        val_cred = Metasploit::Framework::Credential.new(public: username, private: password)
        result = subject.attempt_login(val_cred)
        expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end
    end

    context 'when invalid credentials are entered' do
      let(:response) { failed_res }
      it 'should return an invalid credential object' do
        invalid_cred = Metasploit::Framework::Credential.new(public: username, private: bad_password)
        result = subject.attempt_login(invalid_cred)
        expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
      end
    end
  end
end
