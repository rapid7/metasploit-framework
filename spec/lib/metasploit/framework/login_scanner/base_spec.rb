require 'spec_helper'
require 'metasploit/framework/login_scanner/base'

RSpec.describe Metasploit::Framework::LoginScanner::Base do

  let(:base_class) {
    Class.new do
      include Metasploit::Framework::LoginScanner::Base
      def self.model_name
        ActiveModel::Name.new(self, nil, 'base')
      end
    end
  }

  let(:cred_collection) {
    creds = double('Metasploit::Framework::CredentialCollection')
    allow(creds).to receive(:pass_file)
    allow(creds).to receive(:username).and_return('user')
    allow(creds).to receive(:password).and_return('pass')
    allow(creds).to receive(:user_file)
    allow(creds).to receive(:userpass_file)
    allow(creds).to receive(:prepended_creds).and_return([])
    allow(creds).to receive(:additional_privates).and_return(['pass'])
    allow(creds).to receive(:additional_publics).and_return(['user'])
    allow(creds).to receive(:each).and_return(['user', 'pass'])
    allow(creds).to receive(:additional_publics).and_return([])
    allow(creds).to receive(:empty?).and_return(false)
    creds
  }

  let(:options) {

    {
      connection_timeout: 1,
      cred_details: cred_collection,
      host: '1.2.3.4',
      port: 4444,
      stop_on_success: true,
      bruteforce_speed: 5,

    }
  }

  subject(:login_scanner) {
    base_class.new(options)
  }

  it { is_expected.to respond_to :bruteforce_speed }

  context 'validations' do

    it 'is valid!' do
      expect(login_scanner).to be_valid
    end

    context 'bruteforce_speed' do

      it 'is not valid for a non-number' do
        login_scanner.bruteforce_speed = "a"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:bruteforce_speed]).to include "is not a number"
      end

      it 'is not valid for a float' do
        login_scanner.bruteforce_speed = "3.14"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:bruteforce_speed]).to include "must be an integer"
      end

      it 'is not negative' do
        login_scanner.bruteforce_speed = "-1"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:bruteforce_speed]).to include "must be greater than or equal to 0"
      end

      it 'is nil' do
        login_scanner.bruteforce_speed = nil
        expect(login_scanner).to be_valid
      end

      it 'is not greater than five' do
        login_scanner.bruteforce_speed = "6"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:bruteforce_speed]).to include "must be less than or equal to 5"
      end

    end

    it { is_expected.to respond_to :sleep_time }

    context '#sleep_time' do

      context 'default' do
        subject(:sleep_time) { base_class.new.sleep_time }
        it 'defaults to zero' do
          expect(sleep_time).to eq(0)
        end
      end

      context 'set' do
        subject(:sleep_time) {
          klass = base_class.new
          klass.bruteforce_speed = 0
          klass.sleep_time
        }
        it 'is five minutes when bruteforce_speed is set to 0' do
          expect(sleep_time).to eq(60 * 5)
        end
      end
    end

    it { is_expected.to respond_to :sleep_between_attempts }

    context '#sleep_between_attempts'
    context 'default' do
      subject(:sleep_between_attempts) { base_class.new.sleep_between_attempts }
      it 'returns nothing' do
        expect(sleep_between_attempts).to be_nil
      end
    end

    context 'actually sleep a little' do
      # I don't want to slow down the test, and I don't really know how
      # to test a time interval anyway since rspec disables sleep. :(
    end
  end

end
