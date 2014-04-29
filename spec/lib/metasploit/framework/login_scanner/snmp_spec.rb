require 'spec_helper'
require 'metasploit/framework/login_scanner/snmp'

describe Metasploit::Framework::LoginScanner::SNMP do
  let(:public) { 'public' }
  let(:private) { nil }

  let(:pub_comm) {
    Metasploit::Framework::LoginScanner::Credential.new(
        paired: false,
        public: public,
        private: private
    )
  }

  let(:invalid_detail) {
    Metasploit::Framework::LoginScanner::Credential.new(
        paired: true,
        public: nil,
        private: nil
    )
  }

  let(:detail_group) {
    [ pub_comm ]
  }

  subject(:snmp_scanner) {
    described_class.new
  }

  it { should respond_to :port }
  it { should respond_to :host }
  it { should respond_to :cred_details }
  it { should respond_to :connection_timeout }
  it { should respond_to :stop_on_success }
  it { should respond_to :valid! }
  it { should respond_to :scan! }
  it { should respond_to :proxies }


  context 'validations' do
    context 'port' do

      it 'is not valid for not set' do
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a non-number' do
        snmp_scanner.port = "a"
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        snmp_scanner.port = 5.76
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:port]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        snmp_scanner.port = -8
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        snmp_scanner.port = 0
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for a number greater than 65535' do
        snmp_scanner.port = rand(1000) + 65535
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:port]).to include "must be less than or equal to 65535"
      end

      it 'is valid for a legitimate port number' do
        snmp_scanner.port = rand(65534) + 1
        expect(snmp_scanner.errors[:port]).to be_empty
      end
    end

    context 'host' do

      it 'is not valid for not set' do
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:host]).to include "can't be blank"
      end

      it 'is not valid for a non-string input' do
        snmp_scanner.host = 5
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:host]).to include "must be a string"
      end

      it 'is not valid for an improper IP address' do
        snmp_scanner.host = '192.168.1.1.5'
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an incomplete IP address' do
        snmp_scanner.host = '192.168'
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an invalid IP address' do
        snmp_scanner.host = '192.300.675.123'
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for DNS name that cannot be resolved' do
        snmp_scanner.host = 'nosuchplace.metasploit.com'
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is valid for a valid IP address' do
        snmp_scanner.host = '127.0.0.1'
        expect(snmp_scanner.errors[:host]).to be_empty
      end

      it 'is valid for a DNS name it can resolve' do
        snmp_scanner.host = 'localhost'
        expect(snmp_scanner.errors[:host]).to be_empty
      end
    end

    context 'cred_details' do
      it 'is not valid for not set' do
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:cred_details]).to include "can't be blank"
      end

      it 'is not valid for a non-array input' do
        snmp_scanner.cred_details = rand(10)
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:cred_details]).to include "must be an array"
      end

      it 'is not valid if any of the elements are not a Credential' do
        snmp_scanner.cred_details = [1,2]
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:cred_details]).to include "has invalid element 1"
      end

      it 'is not valid if any of the CredDetails are invalid' do
        snmp_scanner.cred_details = [invalid_detail]
        expect(snmp_scanner).to_not be_valid
      end

      it 'is valid if all of the elements are valid' do
        snmp_scanner.cred_details = [pub_comm]
        expect(snmp_scanner.errors[:cred_details]).to be_empty
      end
    end

    context 'connection_timeout' do

      it 'is not valid for not set' do
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:connection_timeout]).to include "is not a number"
      end

      it 'is not valid for a non-number' do
        snmp_scanner.connection_timeout = "a"
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:connection_timeout]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        snmp_scanner.connection_timeout = 5.76
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:connection_timeout]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        snmp_scanner.connection_timeout = -8
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        snmp_scanner.connection_timeout = 0
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is valid for a legitimate  number' do
        snmp_scanner.port = rand(1000) + 1
        expect(snmp_scanner.errors[:connection_timeout]).to be_empty
      end
    end


    context 'stop_on_success' do

      it 'is not valid for not set' do
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string true' do
        snmp_scanner.stop_on_success = 'true'
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string false' do
        snmp_scanner.stop_on_success = 'false'
        expect(snmp_scanner).to_not be_valid
        expect(snmp_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is  valid for true class' do
        snmp_scanner.stop_on_success = true
        expect(snmp_scanner.errors[:stop_on_success]).to be_empty
      end

      it 'is  valid for false class' do
        snmp_scanner.stop_on_success = false
        expect(snmp_scanner.errors[:stop_on_success]).to be_empty
      end
    end

    context '#valid!' do
      it 'raises a Metasploit::Framework::LoginScanner::Invalid when validations fail' do
        expect{snmp_scanner.valid!}.to raise_error Metasploit::Framework::LoginScanner::Invalid
      end
    end
  end

  context '#attempt_login' do
    before(:each) do
      snmp_scanner.host = '127.0.0.1'
      snmp_scanner.port = 161
      snmp_scanner.connection_timeout = 1
      snmp_scanner.stop_on_success = true
      snmp_scanner.cred_details = detail_group
    end

    it 'creates a Timeout based on the connection_timeout' do
      ::Timeout.should_receive(:timeout).at_least(:once).with(snmp_scanner.connection_timeout)
      snmp_scanner.attempt_login(pub_comm)
    end

    it 'creates a SNMP Manager for each supported version of SNMP' do
      ::SNMP::Manager.should_receive(:new).twice.and_call_original
      snmp_scanner.attempt_login(pub_comm)
    end

  end

  context '#scan!' do
    let(:success) {
      ::Metasploit::Framework::LoginScanner::Result.new(
          private: private,
          proof: '',
          public: public,
          realm: nil,
          status: :success
      )
    }

    let(:failure) {
      ::Metasploit::Framework::LoginScanner::Result.new(
          private: private,
          proof: nil,
          public: public,
          realm: nil,
          status: :failed
      )
    }

    before(:each) do
      snmp_scanner.host = '127.0.0.1'
      snmp_scanner.port = 22
      snmp_scanner.connection_timeout = 1
      snmp_scanner.stop_on_success = false
      snmp_scanner.cred_details = detail_group
    end

    it 'calls valid! before running' do
      my_scanner = snmp_scanner
      my_scanner.should_receive(:scan!).and_call_original
      my_scanner.scan!
    end

    it 'call attempt_login once for each cred_detail' do
      my_scanner = snmp_scanner
      my_scanner.should_receive(:attempt_login).once.with(pub_comm).and_call_original
      my_scanner.scan!
    end

    it 'adds the failed results to the failures attribute' do
      my_scanner = snmp_scanner
      my_scanner.should_receive(:attempt_login).once.with(pub_comm).and_return failure
      my_scanner.scan!
      expect(my_scanner.failures).to include failure
    end

    it 'adds the success results to the successes attribute' do
      my_scanner = snmp_scanner
      my_scanner.should_receive(:attempt_login).once.with(pub_comm).and_return success
      my_scanner.scan!
      expect(my_scanner.successes).to include success
    end

    context 'when stop_on_success is true' do
      before(:each) do
        snmp_scanner.host = '127.0.0.1'
        snmp_scanner.port = 22
        snmp_scanner.connection_timeout = 1
        snmp_scanner.stop_on_success = true
        snmp_scanner.cred_details = detail_group
      end

    end

  end

end