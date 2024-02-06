require 'spec_helper'
require 'metasploit/framework/login_scanner/ldap'

RSpec.shared_examples_for 'Metasploit::Framework::LoginScanner::LDAP' do |ldap_auth_type|
  let(:mock_credential) do
    Metasploit::Framework::Credential.new(
      public: 'mock_public',
      private: 'mock_private',
      realm: 'DEMO.LOCAL'
    )
  end

  let(:public) do
    # SChannel auth doesn't use a username
    ldap_auth_type == Msf::Exploit::Remote::AuthOption::SCHANNEL ? nil : 'root'
  end
  let(:private) do
    # SChannel auth doesn't use a password
    ldap_auth_type == Msf::Exploit::Remote::AuthOption::SCHANNEL ? nil : 'toor'
  end

  let(:realm) { 'myrealm' }
  let(:realm_key) { Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN }

  let(:pub_pri) do
    Metasploit::Framework::Credential.new(
      paired: true,
      public: public,
      private: private
    )
  end

  let(:ad_cred) do
    Metasploit::Framework::Credential.new(
      paired: true,
      public: public,
      private: private,
      realm: realm,
      realm_key: realm_key
    )
  end

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

  describe '#each_credential' do
    context 'when the login_scanner has a realm key' do
      before(:example) do
        subject.realm_key = realm_key
      end
      context 'when the credential has a realm' do
        before(:example) do
          subject.cred_details = [ad_cred]
        end
        it 'set the realm_key on the credential to that of the scanner' do
          output_cred = ad_cred.dup
          output_cred.realm_key = realm_key
          expect { |b| subject.each_credential(&b) }.to yield_with_args(output_cred)
        end
      end

      context 'when the credential has no realm' do
        before(:example) do
          subject.cred_details = [ad_cred]
        end
        it 'yields the original credential' do
          first_cred = ad_cred.dup
          first_cred.realm = nil
          first_cred.realm_key = nil
          expect { |b| subject.each_credential(&b) }.to yield_successive_args(ad_cred)
        end
      end
    end

    context 'when login_scanner has no realm key' do
      context 'when the credential has a realm' do
        before(:example) do
          subject.cred_details = [ad_cred]
        end
        it 'yields the original credential' do
          first_cred = ad_cred.dup
          first_cred.realm = nil
          first_cred.realm_key = nil
          expect { |b| subject.each_credential(&b) }.to yield_successive_args(ad_cred)
        end
      end

      context 'when the credential does not have a realm' do
        before(:example) do
          subject.cred_details = [pub_pri]
        end
        it 'simply yields the original credential' do
          expect { |b| subject.each_credential(&b) }.to yield_with_args(pub_pri)
        end
      end
    end
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

      it_behaves_like 'Metasploit::Framework::LoginScanner::LDAP', auth_type
    end
  end
end
