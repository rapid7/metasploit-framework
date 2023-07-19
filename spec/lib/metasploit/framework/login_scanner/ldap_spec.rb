
require 'spec_helper'
require 'metasploit/framework/login_scanner/ldap'

RSpec.shared_examples_for 'Metasploit::Framework::LoginScanner::LDAP' do

  let(:mock_credential) do
    Metasploit::Framework::Credential.new(
      public: 'mock_public',
      private: 'mock_private',
      realm: 'DEMO.LOCAL'
    )
  end

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: false, has_default_realm: false

  let(:ldap) { spy }
  before(:each) do
    allow(subject).to receive(:ldap_connect_opts).and_return({})
    allow(subject).to receive(:ldap_open).and_yield(ldap)
  end

  it 'successfully authenticates' do
    allow(ldap).to receive(:get_operation_result).and_return(OpenStruct.new(code: 0))

    result = subject.attempt_login(mock_credential)
    expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
  end

  it 'fails to authenticate' do
    allow(ldap).to receive(:get_operation_result).and_return(OpenStruct.new(code: 1))

    result = subject.attempt_login(mock_credential)
    expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
  end


  it 'gracefully handles an exception during authentication' do
    allow(ldap).to receive(:get_operation_result).and_raise(RuntimeError)

    result = subject.attempt_login(mock_credential)
    expect(result.status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
  end
end

RSpec.describe Metasploit::Framework::LoginScanner::LDAP do

  auth_types = [
    Msf::Exploit::Remote::AuthOption::NTLM,
    Msf::Exploit::Remote::AuthOption::KERBEROS,
    Msf::Exploit::Remote::AuthOption::PLAINTEXT,
    Msf::Exploit::Remote::AuthOption::SCHANNEL,
    Msf::Exploit::Remote::AuthOption::AUTO
  ]


  auth_types.each do |auth_type|
    context "#{auth_type} auth" do

      subject(:ldap_scanner) do
        described_class.new(opts: { ldap_auth: auth_type })
      end

      it_behaves_like 'Metasploit::Framework::LoginScanner::LDAP'
    end
  end
end
