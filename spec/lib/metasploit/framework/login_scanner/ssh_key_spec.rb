require 'spec_helper'
require 'metasploit/framework/login_scanner/ssh_key'

describe Metasploit::Framework::LoginScanner::SSHKey do
  let(:public) { 'root' }
  let(:private) { OpenSSL::PKey::RSA.generate(2048).to_s }

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
    [ pub_pri]
  }

  subject(:ssh_scanner) {
    described_class.new
  }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'

  it { should respond_to :port }
  it { should respond_to :host }
  it { should respond_to :cred_details }
  it { should respond_to :connection_timeout }
  it { should respond_to :verbosity }
  it { should respond_to :stop_on_success }
  it { should respond_to :valid! }
  it { should respond_to :scan! }
  it { should respond_to :proxies }


  context 'validations' do
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

  end

  context '#attempt_login' do
    before(:each) do
      ssh_scanner.host = '127.0.0.1'
      ssh_scanner.port = 22
      ssh_scanner.connection_timeout = 30
      ssh_scanner.verbosity = :fatal
      ssh_scanner.stop_on_success = true
      ssh_scanner.cred_details = detail_group
    end

    it 'creates a Timeout based on the connection_timeout' do
      ::Timeout.should_receive(:timeout).with(ssh_scanner.connection_timeout)
      ssh_scanner.attempt_login(pub_pri)
    end

    it 'calls Net::SSH with the correct arguments' do
      opt_hash = {
          :auth_methods  => ['publickey'],
          :port          => ssh_scanner.port,
          :disable_agent => true,
          :key_data      => private,
          :config        => false,
          :verbose       => ssh_scanner.verbosity,
          :proxies       => nil
      }
      Net::SSH.should_receive(:start).with(
          ssh_scanner.host,
          public,
          opt_hash
      )
      ssh_scanner.attempt_login(pub_pri)
    end

    context 'when it fails' do

      it 'returns :connection_error for a Rex::ConnectionError' do
        Net::SSH.should_receive(:start) { raise Rex::ConnectionError }
        expect(ssh_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns :connection_error for a Rex::AddressInUse' do
        Net::SSH.should_receive(:start) { raise Rex::AddressInUse }
        expect(ssh_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a Net::SSH::Disconnect' do
        Net::SSH.should_receive(:start) { raise Net::SSH::Disconnect }
        expect(ssh_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a ::EOFError' do
        Net::SSH.should_receive(:start) { raise ::EOFError }
        expect(ssh_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns :connection_disconnect for a ::Timeout::Error' do
        Net::SSH.should_receive(:start) { raise ::Timeout::Error }
        expect(ssh_scanner.attempt_login(pub_pri).status).to eq :connection_error
      end

      it 'returns [:fail,nil] for a Net::SSH::Exception' do
        Net::SSH.should_receive(:start) { raise Net::SSH::Exception }
        expect(ssh_scanner.attempt_login(pub_pri).status).to eq :failed
      end

      it 'returns [:fail,nil] if no socket returned' do
        Net::SSH.should_receive(:start).and_return nil
        expect(ssh_scanner.attempt_login(pub_pri).status).to eq :failed
      end
    end

    context 'when it succeeds' do

      it 'gathers proof of the connections' do
        Net::SSH.should_receive(:start) {"fake_socket"}
        my_scanner = ssh_scanner
        my_scanner.should_receive(:gather_proof)
        my_scanner.attempt_login(pub_pri)
      end

      it 'returns a success code and proof' do
        Net::SSH.should_receive(:start) {"fake_socket"}
        my_scanner = ssh_scanner
        my_scanner.should_receive(:gather_proof).and_return(public)
        expect(my_scanner.attempt_login(pub_pri).status).to eq :success
      end
    end
  end


end