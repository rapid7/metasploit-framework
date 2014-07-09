
shared_examples_for 'Metasploit::Framework::LoginScanner::Base' do

  subject(:login_scanner) { described_class.new }

  let(:public) { 'root' }
  let(:private) { 'toor' }

  let(:pub_blank) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: ''
    )
  }

  let(:pub_pub) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: public
    )
  }

  let(:pub_pri) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: private
    )
  }

  let(:invalid_detail) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: nil,
        private: nil
    )
  }

  let(:detail_group) {
    [ pub_blank, pub_pub, pub_pri]
  }

  it { should respond_to :connection_timeout }
  it { should respond_to :cred_details }
  it { should respond_to :host }
  it { should respond_to :port }
  it { should respond_to :proxies }
  it { should respond_to :stop_on_success }

  context 'validations' do
    context 'port' do

      it 'is not valid for a non-number' do
        login_scanner.port = "a"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        login_scanner.port = 5.76
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:port]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        login_scanner.port = -8
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        login_scanner.port = 0
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for a number greater than 65535' do
        login_scanner.port = 65536
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:port]).to include "must be less than or equal to 65535"
      end

      it 'is valid for a legitimate port number' do
        login_scanner.port = rand(65534) + 1
        expect(login_scanner.errors[:port]).to be_empty
      end
    end

    context 'host' do

      it 'is not valid for not set' do
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:host]).to include "can't be blank"
      end

      it 'is not valid for a non-string input' do
        login_scanner.host = 5
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:host]).to include "must be a string"
      end

      it 'is not valid for an improper IP address' do
        login_scanner.host = '192.168.1.1.5'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an incomplete IP address' do
        login_scanner.host = '192.168'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an invalid IP address' do
        login_scanner.host = '192.300.675.123'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for DNS name that cannot be resolved' do
        login_scanner.host = 'nosuchplace.metasploit.com'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is valid for a valid IP address' do
        login_scanner.host = '127.0.0.1'
        expect(login_scanner.errors[:host]).to be_empty
      end

      it 'is valid for a DNS name it can resolve' do
        login_scanner.host = 'localhost'
        expect(login_scanner.errors[:host]).to be_empty
      end
    end

    context 'cred_details' do
      it 'is not valid for not set' do
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:cred_details]).to include "can't be blank"
      end

      it 'is not valid for a non-array input' do
        login_scanner.cred_details = rand(10)
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:cred_details]).to include "must respond to :each"
      end

    end

    context 'connection_timeout' do

      it 'is not valid for a non-number' do
        login_scanner.connection_timeout = "a"
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:connection_timeout]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        login_scanner.connection_timeout = 5.76
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:connection_timeout]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        login_scanner.connection_timeout = -8
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        login_scanner.connection_timeout = 0
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:connection_timeout]).to include "must be greater than or equal to 1"
      end

      it 'is valid for a legitimate  number' do
        login_scanner.port = rand(1000) + 1
        expect(login_scanner.errors[:connection_timeout]).to be_empty
      end
    end

    context 'stop_on_success' do

      it 'is not valid for not set' do
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string true' do
        login_scanner.stop_on_success = 'true'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is not valid for the string false' do
        login_scanner.stop_on_success = 'false'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:stop_on_success]).to include 'is not included in the list'
      end

      it 'is  valid for true class' do
        login_scanner.stop_on_success = true
        expect(login_scanner.errors[:stop_on_success]).to be_empty
      end

      it 'is  valid for false class' do
        login_scanner.stop_on_success = false
        expect(login_scanner.errors[:stop_on_success]).to be_empty
      end
    end

    context '#valid!' do
      it 'raises a Metasploit::Framework::LoginScanner::Invalid when validations fail' do
        expect{login_scanner.valid!}.to raise_error Metasploit::Framework::LoginScanner::Invalid
      end
    end
  end

  context '#scan!' do
    let(:success) {
      ::Metasploit::Framework::LoginScanner::Result.new(
          credential: pub_pub,
          proof: '',
          status: :success
      )
    }

    let(:failure_blank) {
      ::Metasploit::Framework::LoginScanner::Result.new(
          credential: pub_blank,
          proof: nil,
          status: :failed
      )
    }

    before(:each) do
      login_scanner.host = '127.0.0.1'
      login_scanner.port = 22
      login_scanner.connection_timeout = 30
      login_scanner.stop_on_success = false
      login_scanner.cred_details = detail_group
    end

    it 'calls valid! before running' do
      my_scanner = login_scanner
      my_scanner.should_receive(:valid!)
      my_scanner.should_receive(:attempt_login).at_least(:once).and_return success
      my_scanner.scan!
    end

    it 'call attempt_login once for each cred_detail' do
      my_scanner = login_scanner
      my_scanner.should_receive(:valid!)
      my_scanner.should_receive(:attempt_login).once.with(pub_blank).and_return success
      my_scanner.should_receive(:attempt_login).once.with(pub_pub).and_return success
      my_scanner.should_receive(:attempt_login).once.with(pub_pri).and_return success
      my_scanner.scan!
    end

    context 'when stop_on_success is true' do
      before(:each) do
        login_scanner.host = '127.0.0.1'
        login_scanner.port = 22
        login_scanner.connection_timeout = 30
        login_scanner.stop_on_success = true
        login_scanner.cred_details = detail_group
      end

      it 'stops after the first successful login' do
        my_scanner = login_scanner
        my_scanner.should_receive(:valid!)
        my_scanner.should_receive(:attempt_login).once.with(pub_blank).and_return failure_blank
        my_scanner.should_receive(:attempt_login).once.with(pub_pub).and_return success
        my_scanner.should_not_receive(:attempt_login).with(pub_pri)
        my_scanner.scan!
      end
    end

  end
end
