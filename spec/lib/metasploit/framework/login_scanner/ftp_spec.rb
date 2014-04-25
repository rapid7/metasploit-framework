require 'spec_helper'
require 'metasploit/framework/login_scanner/ftp'

describe Metasploit::Framework::LoginScanner::FTP do
  let(:public) { 'root' }
  let(:private) { 'toor' }

  let(:pub_blank) {
    Metasploit::Framework::LoginScanner::Credential.new(
        paired: true,
        public: public,
        private: ''
    )
  }

  let(:pub_pub) {
    Metasploit::Framework::LoginScanner::Credential.new(
        paired: true,
        public: public,
        private: public
    )
  }

  let(:pub_pri) {
    Metasploit::Framework::LoginScanner::Credential.new(
        paired: true,
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
    [ pub_blank, pub_pub, pub_pri]
  }

  subject(:ftp_scanner) {
    described_class.new
  }

  it { should respond_to :port }
  it { should respond_to :host }
  it { should respond_to :cred_details }
  it { should respond_to :connection_timeout }
  it { should respond_to :stop_on_success }
  it { should respond_to :valid! }
  it { should respond_to :scan! }


  context 'validations' do
    context 'port' do

      it 'is not valid for not set' do
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a non-number' do
        ftp_scanner.port = "a"
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        ftp_scanner.port = 5.76
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:port]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        ftp_scanner.port = -8
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        ftp_scanner.port = 0
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for a number greater than 65535' do
        ftp_scanner.port = rand(1000) + 65535
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:port]).to include "must be less than or equal to 65535"
      end

      it 'is valid for a legitimate port number' do
        ftp_scanner.port = rand(65534) + 1
        expect(ftp_scanner.errors[:port]).to be_empty
      end
    end

    context 'host' do

      it 'is not valid for not set' do
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:host]).to include "can't be blank"
      end

      it 'is not valid for a non-string input' do
        ftp_scanner.host = 5
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:host]).to include "must be a string"
      end

      it 'is not valid for an improper IP address' do
        ftp_scanner.host = '192.168.1.1.5'
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an incomplete IP address' do
        ftp_scanner.host = '192.168'
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an invalid IP address' do
        ftp_scanner.host = '192.300.675.123'
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for DNS name that cannot be resolved' do
        ftp_scanner.host = 'nosuchplace.metasploit.com'
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is valid for a valid IP address' do
        ftp_scanner.host = '127.0.0.1'
        expect(ftp_scanner.errors[:host]).to be_empty
      end

      it 'is valid for a DNS name it can resolve' do
        ftp_scanner.host = 'localhost'
        expect(ftp_scanner.errors[:host]).to be_empty
      end
    end

    context 'cred_details' do
      it 'is not valid for not set' do
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:cred_details]).to include "can't be blank"
      end

      it 'is not valid for a non-array input' do
        ftp_scanner.cred_details = rand(10)
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:cred_details]).to include "must be an array"
      end

      it 'is not valid if any of the elements are not a Credential' do
        ftp_scanner.cred_details = [1,2]
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:cred_details]).to include "has invalid element 1"
      end

      it 'is not valid if any of the CredDetails are invalid' do
        ftp_scanner.cred_details = [pub_blank, invalid_detail]
        expect(ftp_scanner).to_not be_valid
      end

      it 'is valid if all of the elements are valid' do
        ftp_scanner.cred_details = [pub_blank, pub_pub, pub_pri]
        expect(ftp_scanner.errors[:cred_details]).to be_empty
      end
    end

    context 'connection_timeout' do

      it 'is not valid for not set' do
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:connection_timeout]).to include "is not a number"
      end

      it 'is not valid for a non-number' do
        ftp_scanner.connection_timeout = "a"
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:connection_timeout]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        ftp_scanner.connection_timeout = 5.76
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:connection_timeout]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        ftp_scanner.connection_timeout = -8
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        ftp_scanner.connection_timeout = 0
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is valid for a legitimate  number' do
        ftp_scanner.port = rand(1000) + 1
        expect(ftp_scanner.errors[:connection_timeout]).to be_empty
      end
    end


    context 'stop_on_success' do

      it 'is not valid for not set' do
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string true' do
        ftp_scanner.stop_on_success = 'true'
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string false' do
        ftp_scanner.stop_on_success = 'false'
        expect(ftp_scanner).to_not be_valid
        expect(ftp_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is  valid for true class' do
        ftp_scanner.stop_on_success = true
        expect(ftp_scanner.errors[:stop_on_success]).to be_empty
      end

      it 'is  valid for false class' do
        ftp_scanner.stop_on_success = false
        expect(ftp_scanner.errors[:stop_on_success]).to be_empty
      end
    end

    context '#valid!' do
      it 'raises a Metasploit::Framework::LoginScanner::Invalid when validations fail' do
        expect{ftp_scanner.valid!}.to raise_error Metasploit::Framework::LoginScanner::Invalid
      end
    end
  end

  context '#attempt_login' do
    before(:each) do
      ftp_scanner.host = '127.0.0.1'
      ftp_scanner.port = 21
      ftp_scanner.connection_timeout = 30
      ftp_scanner.ftp_timeout = 16
      ftp_scanner.stop_on_success = true
      ftp_scanner.cred_details = detail_group
    end


    context 'when it fails' do

      it 'returns :connection_error for a Rex::ConnectionError' do
        Rex::Socket::Tcp.should_receive(:create) { raise Rex::ConnectionError }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns :connection_error for a Rex::AddressInUse' do
        Rex::Socket::Tcp.should_receive(:create) { raise Rex::AddressInUse }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a ::EOFError' do
        Rex::Socket::Tcp.should_receive(:create) { raise ::EOFError }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a ::Timeout::Error' do
        Rex::Socket::Tcp.should_receive(:create) { raise ::Timeout::Error }
        expect(ftp_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

    end

    context 'when it succeeds' do


    end
  end

  context '#scan!' do
    let(:success) {
      ::Metasploit::Framework::LoginScanner::Result.new(
          private: public,
          proof: '',
          public: public,
          realm: nil,
          status: :success
      )
    }

    let(:failure_blank) {
      ::Metasploit::Framework::LoginScanner::Result.new(
          private: '',
          proof: nil,
          public: public,
          realm: nil,
          status: :failed
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
      ftp_scanner.host = '127.0.0.1'
      ftp_scanner.port = 21
      ftp_scanner.connection_timeout = 30
      ftp_scanner.ftp_timeout = 16
      ftp_scanner.stop_on_success = false
      ftp_scanner.cred_details = detail_group
    end

    it 'calls valid! before running' do
      my_scanner = ftp_scanner
      my_scanner.should_receive(:scan!).and_call_original
      my_scanner.scan!
    end

    it 'call attempt_login once for each cred_detail' do
      my_scanner = ftp_scanner
      my_scanner.should_receive(:attempt_login).once.with(pub_blank).and_call_original
      my_scanner.should_receive(:attempt_login).once.with(pub_pub).and_call_original
      my_scanner.should_receive(:attempt_login).once.with(pub_pri).and_call_original
      my_scanner.scan!
    end

    it 'adds the failed results to the failures attribute' do
      my_scanner = ftp_scanner
      my_scanner.should_receive(:attempt_login).once.with(pub_blank).and_return failure_blank
      my_scanner.should_receive(:attempt_login).once.with(pub_pub).and_return success
      my_scanner.should_receive(:attempt_login).once.with(pub_pri).and_return failure
      my_scanner.scan!
      expect(my_scanner.failures).to include failure_blank
      expect(my_scanner.failures).to include failure
    end

    it 'adds the success results to the successes attribute' do
      my_scanner = ftp_scanner
      my_scanner.should_receive(:attempt_login).once.with(pub_blank).and_return failure_blank
      my_scanner.should_receive(:attempt_login).once.with(pub_pub).and_return success
      my_scanner.should_receive(:attempt_login).once.with(pub_pri).and_return failure
      my_scanner.scan!
      expect(my_scanner.successes).to include success
    end

    context 'when stop_on_success is true' do
      before(:each) do
        ftp_scanner.host = '127.0.0.1'
        ftp_scanner.port = 21
        ftp_scanner.connection_timeout = 30
        ftp_scanner.ftp_timeout = 16
        ftp_scanner.stop_on_success = true
        ftp_scanner.cred_details = detail_group
      end

      it 'stops after the first successful login' do
        my_scanner = ftp_scanner
        my_scanner.should_receive(:attempt_login).once.with(pub_blank).and_return failure_blank
        my_scanner.should_receive(:attempt_login).once.with(pub_pub).and_return success
        my_scanner.should_not_receive(:attempt_login).with(pub_pri)
        my_scanner.scan!
        expect(my_scanner.failures).to_not include failure
      end
    end

  end

end