require 'spec_helper'
require 'metasploit/framework/login_scanner'

describe Metasploit::Framework::LoginScanner::SSH do
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

  subject(:ssh_scanner) {
    described_class.new
  }

  it { should respond_to :port }
  it { should respond_to :host }
  it { should respond_to :cred_details }
  it { should respond_to :connection_timeout }
  it { should respond_to :verbosity }
  it { should respond_to :stop_on_success }
  it { should respond_to :valid! }
  it { should respond_to :scan! }


  context 'validations' do
    context 'port' do

      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a non-number' do
        ssh_scanner.port = "a"
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        ssh_scanner.port = 5.76
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        ssh_scanner.port = -8
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        ssh_scanner.port = 0
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for a number greater than 65535' do
        ssh_scanner.port = rand(1000) + 65535
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be less than or equal to 65535"
      end

      it 'is valid for a legitimate port number' do
        ssh_scanner.port = rand(65534) + 1
        expect(ssh_scanner.errors[:port]).to be_empty
      end
    end

    context 'host' do

      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "can't be blank"
      end

      it 'is not valid for a non-string input' do
        ssh_scanner.host = 5
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "must be a string"
      end

      it 'is not valid for an improper IP address' do
        ssh_scanner.host = '192.168.1.1.5'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an incomplete IP address' do
        ssh_scanner.host = '192.168'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an invalid IP address' do
        ssh_scanner.host = '192.300.675.123'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for DNS name that cannot be resolved' do
        ssh_scanner.host = 'nosuchplace.metasploit.com'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is valid for a valid IP address' do
        ssh_scanner.host = '127.0.0.1'
        expect(ssh_scanner.errors[:host]).to be_empty
      end

      it 'is valid for a DNS name it can resolve' do
        ssh_scanner.host = 'localhost'
        expect(ssh_scanner.errors[:host]).to be_empty
      end
    end

    context 'cred_details' do
      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "can't be blank"
      end

      it 'is not valid for a non-array input' do
        ssh_scanner.cred_details = rand(10)
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "must be an array"
      end

      it 'is not valid if any of the elements are not a Credential' do
        ssh_scanner.cred_details = [1,2]
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "has invalid element 1"
      end

      it 'is not valid if any of the CredDetails are invalid' do
        ssh_scanner.cred_details = [pub_blank, invalid_detail]
        expect(ssh_scanner).to_not be_valid
      end

      it 'is valid if all of the elements are valid' do
        ssh_scanner.cred_details = [pub_blank, pub_pub, pub_pri]
        expect(ssh_scanner.errors[:cred_details]).to be_empty
      end
    end

    context 'connection_timeout' do

      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:connection_timeout]).to include "is not a number"
      end

      it 'is not valid for a non-number' do
        ssh_scanner.connection_timeout = "a"
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:connection_timeout]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        ssh_scanner.connection_timeout = 5.76
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:connection_timeout]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        ssh_scanner.connection_timeout = -8
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        ssh_scanner.connection_timeout = 0
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is valid for a legitimate  number' do
        ssh_scanner.port = rand(1000) + 1
        expect(ssh_scanner.errors[:connection_timeout]).to be_empty
      end
    end

    context 'verbosity' do

      it 'is valid with :debug' do
        ssh_scanner.verbosity = :debug
        expect(ssh_scanner.errors[:verbosity]).to be_empty
      end

      it 'is valid with :info' do
        ssh_scanner.verbosity = :info
        expect(ssh_scanner.errors[:verbosity]).to be_empty
      end

      it 'is valid with :warn' do
        ssh_scanner.verbosity = :warn
        expect(ssh_scanner.errors[:verbosity]).to be_empty
      end

      it 'is valid with :error' do
        ssh_scanner.verbosity = :error
        expect(ssh_scanner.errors[:verbosity]).to be_empty
      end

      it 'is valid with :fatal' do
        ssh_scanner.verbosity = :fatal
        expect(ssh_scanner.errors[:verbosity]).to be_empty
      end

      it 'is invalid with a random symbol' do
        ssh_scanner.verbosity = :foobar
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:verbosity]).to include 'is not included in the list'
      end

      it 'is invalid with a string' do
        ssh_scanner.verbosity = 'debug'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:verbosity]).to include 'is not included in the list'
      end
    end

    context 'stop_on_success' do

      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string true' do
        ssh_scanner.stop_on_success = 'true'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string false' do
        ssh_scanner.stop_on_success = 'false'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is  valid for true class' do
        ssh_scanner.stop_on_success = true
        expect(ssh_scanner.errors[:stop_on_success]).to be_empty
      end

      it 'is  valid for false class' do
        ssh_scanner.stop_on_success = false
        expect(ssh_scanner.errors[:stop_on_success]).to be_empty
      end
    end

    context '#valid!' do
      it 'raises a Metasploit::Framework::LoginScanner::Invalid when validations fail' do
        expect{ssh_scanner.valid!}.to raise_error Metasploit::Framework::LoginScanner::Invalid
      end
    end
  end

  context '#attempt_login' do
    before(:each) do
      ssh_scanner.host = '127.0.0.1'
      ssh_scanner.port = 22
      ssh_scanner.connection_timeout = 30
      ssh_scanner.verbosity = :fatal
      ssh_scanner.stop_on_success = true
      ssh_scanner.cred_details = [ { public: public, private: private}]
    end

    it 'creates a Timeout based on the connection_timeout' do
      ::Timeout.should_receive(:timeout).with(ssh_scanner.connection_timeout)
      ssh_scanner.attempt_login(public, private)
    end

    it 'calls Net::SSH with the correct arguments' do
      opt_hash = {
          :auth_methods  => ['password','keyboard-interactive'],
          :port          => ssh_scanner.port,
          :disable_agent => true,
          :password      => private,
          :config        => false,
          :verbose       => ssh_scanner.verbosity
      }
      Net::SSH.should_receive(:start).with(
          ssh_scanner.host,
          public,
          opt_hash
      )
      ssh_scanner.attempt_login(public, private)
    end

    context 'when it fails' do

      it 'returns :connection_error for a Rex::ConnectionError' do
        Net::SSH.should_receive(:start) { raise Rex::ConnectionError }
        expect(ssh_scanner.attempt_login(public, private).status).to eq :connection_error
      end

      it 'returns :connection_error for a Rex::AddressInUse' do
        Net::SSH.should_receive(:start) { raise Rex::AddressInUse }
        expect(ssh_scanner.attempt_login(public, private).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a Net::SSH::Disconnect' do
        Net::SSH.should_receive(:start) { raise Net::SSH::Disconnect }
        expect(ssh_scanner.attempt_login(public, private).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a ::EOFError' do
        Net::SSH.should_receive(:start) { raise ::EOFError }
        expect(ssh_scanner.attempt_login(public, private).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a ::Timeout::Error' do
        Net::SSH.should_receive(:start) { raise ::Timeout::Error }
        expect(ssh_scanner.attempt_login(public, private).status).to eq :connection_error
      end

      it 'returns [:fail,nil] for a Net::SSH::Exception' do
        Net::SSH.should_receive(:start) { raise Net::SSH::Exception }
        expect(ssh_scanner.attempt_login(public, private).status).to eq :failed
      end

      it 'returns [:fail,nil] if no socket returned' do
        Net::SSH.should_receive(:start).and_return nil
        expect(ssh_scanner.attempt_login(public, private).status).to eq :failed
      end
    end

    context 'when it succeeds' do

      it 'gathers proof of the connections' do
        Net::SSH.should_receive(:start) {"fake_socket"}
        my_scanner = ssh_scanner
        my_scanner.should_receive(:gather_proof)
        my_scanner.attempt_login(public, private)
      end

      it 'returns a success code and proof' do
        Net::SSH.should_receive(:start) {"fake_socket"}
        my_scanner = ssh_scanner
        my_scanner.should_receive(:gather_proof).and_return(public)
        expect(my_scanner.attempt_login(public, private).status).to eq :success
      end
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
      ssh_scanner.host = '127.0.0.1'
      ssh_scanner.port = 22
      ssh_scanner.connection_timeout = 30
      ssh_scanner.verbosity = :fatal
      ssh_scanner.stop_on_success = false
      ssh_scanner.cred_details = detail_group
    end

    it 'calls valid! before running' do
      my_scanner = ssh_scanner
      my_scanner.should_receive(:scan!).and_call_original
      my_scanner.scan!
    end

    it 'call attempt_login once for each cred_detail' do
      my_scanner = ssh_scanner
      my_scanner.should_receive(:attempt_login).once.with(public, '').and_call_original
      my_scanner.should_receive(:attempt_login).once.with(public, public).and_call_original
      my_scanner.should_receive(:attempt_login).once.with(public, private).and_call_original
      my_scanner.scan!
    end

    it 'adds the failed results to the failures attribute' do
      my_scanner = ssh_scanner
      my_scanner.should_receive(:attempt_login).once.with(public, '').and_return failure_blank
      my_scanner.should_receive(:attempt_login).once.with(public, public).and_return success
      my_scanner.should_receive(:attempt_login).once.with(public, private).and_return failure
      my_scanner.scan!
      expect(my_scanner.failures).to include failure_blank
      expect(my_scanner.failures).to include failure
    end

    it 'adds the success results to the successes attribute' do
      my_scanner = ssh_scanner
      my_scanner.should_receive(:attempt_login).once.with(public, '').and_return failure_blank
      my_scanner.should_receive(:attempt_login).once.with(public, public).and_return success
      my_scanner.should_receive(:attempt_login).once.with(public, private).and_return failure
      my_scanner.scan!
      expect(my_scanner.successes).to include success
    end

    context 'when stop_on_success is true' do
      before(:each) do
        ssh_scanner.host = '127.0.0.1'
        ssh_scanner.port = 22
        ssh_scanner.connection_timeout = 30
        ssh_scanner.verbosity = :fatal
        ssh_scanner.stop_on_success = true
        ssh_scanner.cred_details = detail_group
      end

      it 'stops after the first successful login' do
        my_scanner = ssh_scanner
        my_scanner.should_receive(:attempt_login).once.with(public, '').and_return failure_blank
        my_scanner.should_receive(:attempt_login).once.with(public, public).and_return success
        my_scanner.should_not_receive(:attempt_login).with(public, private)
        my_scanner.scan!
        expect(my_scanner.failures).to_not include failure
      end
    end

  end

end