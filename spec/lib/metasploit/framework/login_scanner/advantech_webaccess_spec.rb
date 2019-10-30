require 'spec_helper'
require 'metasploit/framework/login_scanner/advantech_webaccess'

RSpec.describe Metasploit::Framework::LoginScanner::AdvantechWebAccess do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

    subject do
      described_class.new
    end

    let(:successful_auth_response) do
      res = Rex::Proto::Http::Response.new(302, 'Found')
      res.headers['Location'] = '/broadweb/bwproj.asp'
      res
    end

    let(:fail_auth_response) do
      Rex::Proto::Http::Response.new(200, 'OK')
    end

    describe '#attempt_login' do

      context 'when the credential is valid' do
        let(:username) { 'user' }
        let(:password) { 'goddpass' }

        before do
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(successful_auth_response)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
        end

        it 'returns a Result object indicating a successful login' do
          cred = Metasploit::Framework::Credential.new(public: username, private: password)
          result = subject.attempt_login(cred)
          expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when the credential is invalid' do
        let(:username) { 'admin' }
        let(:password) { 'badpass' }

        before(:example) do
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(fail_auth_response)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
          allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
        end

        it 'returns a Result object indicating a failed login' do
          cred = Metasploit::Framework::Credential.new(public: username, private: password)
          result = subject.attempt_login(cred)
          expect(result).to be_kind_of(Metasploit::Framework::LoginScanner::Result)
          expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end
    end


end
