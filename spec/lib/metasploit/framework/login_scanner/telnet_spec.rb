require 'spec_helper'
require 'metasploit/framework/login_scanner/telnet'

RSpec.describe Metasploit::Framework::LoginScanner::Telnet do

  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: false, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::Tcp::Client'

  it { is_expected.to respond_to :banner_timeout }
  it { is_expected.to respond_to :telnet_timeout }

  before(:each) do
    creds = double('Metasploit::Framework::CredentialCollection')
    allow(creds).to receive(:pass_file)
    allow(creds).to receive(:username)
    allow(creds).to receive(:password)
    allow(creds).to receive(:user_file)
    allow(creds).to receive(:userpass_file)
    allow(creds).to receive(:prepended_creds).and_return([])
    allow(creds).to receive(:additional_privates).and_return([])
    allow(creds).to receive(:additional_publics).and_return([])
    allow(creds).to receive(:empty?).and_return(true)
    login_scanner.cred_details = creds
  end

  context 'validations' do
    context 'banner_timeout' do
      it 'is not valid for a non-number' do
        login_scanner.banner_timeout = "a"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:banner_timeout]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        login_scanner.banner_timeout = 5.76
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:banner_timeout]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        login_scanner.banner_timeout = -8
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:banner_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        login_scanner.banner_timeout = 0
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:banner_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is valid for a legitimate number' do
        login_scanner.port = rand(1000) + 1
        expect(login_scanner.errors[:banner_timeout]).to be_empty
      end
    end

    context 'telnet_timeout' do
      it 'is not valid for a non-number' do
        login_scanner.telnet_timeout = "a"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:telnet_timeout]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        login_scanner.telnet_timeout = 5.76
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:telnet_timeout]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        login_scanner.telnet_timeout = -8
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:telnet_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        login_scanner.telnet_timeout = 0
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:telnet_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is valid for a legitimate number' do
        login_scanner.port = rand(1000) + 1
        expect(login_scanner.errors[:telnet_timeout]).to be_empty
      end
    end
  end

end
