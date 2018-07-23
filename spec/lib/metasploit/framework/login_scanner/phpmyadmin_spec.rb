require 'spec_helper'
require 'metasploit/framework/login_scanner/phpmyadmin'

RSpec.describe Metasploit::Framework::LoginScanner::PhpMyAdmin do
  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  subject do
    described_class.new
  end

  let(:response) do
    Rex::Proto::Http::Response.new(200, 'OK')
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
      res.body = '<h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1>'
      res
    end

    context 'when the target is PhpMyAdmin' do
      let(:response) { phpMyAdmin_res }
        it 'should return true' do
          expect(subject.check_setup).to eql(true)
        end
    end

    context 'when the target is not PhpMyAdmin' do
      it 'should return false' do
        expect(subject.check_setup).to eql(false)
      end
    end
  end

  describe '#get_session_info' do
    let(:response) { nil }
      context 'when a bad request is sent' do
        it 'should return an unable to connect status' do
          expect(subject.get_session_info).to eql({ status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to access PhpMyAdmin login page' })
      end
    end

  end

  describe '#do_login' do

  end

  describe '#attempt_login' do

  end
end
