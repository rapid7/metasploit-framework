
RSpec.shared_examples_for 'Metasploit::Framework::LoginScanner::Base' do | opts |

  subject(:login_scanner) { described_class.new }

  let(:public) { 'root' }
  let(:private) { 'toor' }
  let(:realm) { 'myrealm' }
  let(:realm_key) { Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN }

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

  let(:ad_cred) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: public,
        private: private,
        realm: realm,
        realm_key: realm_key
    )
  }

  let(:detail_group) {
    [ pub_blank, pub_pub, pub_pri]
  }

  let(:socket_error) {
    ::SocketError.new("getaddrinfo: nodename nor servname provided, or not known")
  }

  it { is_expected.to respond_to :connection_timeout }
  it { is_expected.to respond_to :cred_details }
  it { is_expected.to respond_to :host }
  it { is_expected.to respond_to :port }
  it { is_expected.to respond_to :proxies }
  it { is_expected.to respond_to :stop_on_success }

  before do
    creds = double('Metasploit::Framework::CredentialCollection')
    allow(creds).to receive(:pass_file)
    allow(creds).to receive(:username)
    allow(creds).to receive(:password)
    allow(creds).to receive(:user_file)
    allow(creds).to receive(:userpass_file)
    allow(creds).to receive(:prepended_creds).and_return([])
    allow(creds).to receive(:additional_privates).and_return([])
    allow(creds).to receive(:additional_publics).and_return(['user'])
    allow(creds).to receive(:empty?).and_return(true)
    login_scanner.cred_details = creds
  end

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
      before do
        allow(::Rex::Socket).to receive(:getaddress).with('192.168.1.1.5', true).and_raise(socket_error)
        allow(::Rex::Socket).to receive(:getaddress).with('192.168', true).and_return('192.0.0.168')
        allow(::Rex::Socket).to receive(:getaddress).with('192.300.675.123', true).and_raise(socket_error)
        allow(::Rex::Socket).to receive(:getaddress).with('nosuchplace.metasploit.com', true).and_raise(socket_error)
      end

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
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:cred_details]).to include "can't be blank"
      end

      it 'is not valid for a non-array input' do
        creds = double('Metasploit::Framework::CredentialCollection')
        allow(creds).to receive(:pass_file)
        allow(creds).to receive(:pass_file)
        allow(creds).to receive(:username)
        allow(creds).to receive(:password)
        allow(creds).to receive(:user_file)
        allow(creds).to receive(:userpass_file)
        allow(creds).to receive(:prepended_creds).and_return([])
        allow(creds).to receive(:additional_privates).and_return([])
        allow(creds).to receive(:additional_publics).and_return(['user'])
        allow(creds).to receive(:empty?).and_return(true)
        login_scanner.cred_details = creds
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
          status:  Metasploit::Model::Login::Status::SUCCESSFUL
      )
    }

    let(:failure_blank) {
      ::Metasploit::Framework::LoginScanner::Result.new(
          credential: pub_blank,
          proof: nil,
          status: Metasploit::Model::Login::Status::INCORRECT
      )
    }

    before(:example) do
      login_scanner.host = '127.0.0.1'
      login_scanner.port = 22
      login_scanner.connection_timeout = 30
      login_scanner.stop_on_success = false
      login_scanner.cred_details = detail_group
    end

    it 'calls valid! before running' do
      my_scanner = login_scanner
      expect(my_scanner).to receive(:valid!)
      expect(my_scanner).to receive(:attempt_login).at_least(:once).and_return success
      my_scanner.scan!
    end

    it 'should stop trying a user after success' do
      my_scanner = login_scanner
      expect(my_scanner).to receive(:valid!)
      expect(my_scanner).to receive(:attempt_login).once.with(pub_blank).and_return failure_blank
      expect(my_scanner).to receive(:attempt_login).once.with(pub_pub).and_return success
      expect(my_scanner).not_to receive(:attempt_login)
      my_scanner.scan!
    end

    it 'call attempt_login once for each cred_detail' do
      my_scanner = login_scanner
      expect(my_scanner).to receive(:valid!)
      expect(my_scanner).to receive(:attempt_login).once.with(pub_blank).and_return failure_blank
      expect(my_scanner).to receive(:attempt_login).once.with(pub_pub).and_return failure_blank
      expect(my_scanner).to receive(:attempt_login).once.with(pub_pri).and_return failure_blank
      my_scanner.scan!
    end

    context 'when stop_on_success is true' do
      before(:example) do
        login_scanner.host = '127.0.0.1'
        login_scanner.port = 22
        login_scanner.connection_timeout = 30
        login_scanner.stop_on_success = true
        login_scanner.cred_details = detail_group
      end

      it 'stops after the first successful login' do
        my_scanner = login_scanner
        expect(my_scanner).to receive(:valid!)
        expect(my_scanner).to receive(:attempt_login).once.with(pub_blank).and_return failure_blank
        expect(my_scanner).to receive(:attempt_login).once.with(pub_pub).and_return success
        expect(my_scanner).not_to receive(:attempt_login).with(pub_pri)
        my_scanner.scan!
      end
    end

  end

  context '#each_credential' do

    if opts[:has_realm_key]
      context 'when the login_scanner has a REALM_KEY' do
        context 'when the credential has a realm' do
          before(:example) do
            login_scanner.cred_details = [ad_cred]
          end
          it 'set the realm_key on the credential to that of the scanner' do
            output_cred = ad_cred.dup
            output_cred.realm_key = described_class::REALM_KEY
            expect{ |b| login_scanner.each_credential(&b)}.to yield_with_args(output_cred)
          end
        end

        if opts[:has_default_realm]
          context 'when the credential has no realm' do
            before(:example) do
              login_scanner.cred_details = [pub_pri]
            end
            it 'uses the default realm' do
              output_cred = pub_pri.dup
              output_cred.realm = described_class::DEFAULT_REALM
              output_cred.realm_key = described_class::REALM_KEY
              expect{ |b| login_scanner.each_credential(&b)}.to yield_with_args(output_cred)
            end
          end
        end

      end
    else
      context 'when login_scanner has no REALM_KEY' do
        context 'when the credential has a realm' do
          before(:example) do
            login_scanner.cred_details = [ad_cred]
          end
          it 'yields the original credential as well as one with the realm in the public' do
            first_cred  = ad_cred.dup
            first_cred.realm = nil
            first_cred.realm_key = nil
            second_cred = first_cred.dup
            second_cred.public = "#{realm}\\#{public}"
            expect{ |b| login_scanner.each_credential(&b)}.to yield_successive_args(ad_cred,second_cred)
          end
        end

        context 'when the credential does not have a realm' do
          before(:example) do
            login_scanner.cred_details = [pub_pri]
          end
          it 'simply yields the original credential' do
            expect{ |b| login_scanner.each_credential(&b)}.to yield_with_args(pub_pri)
          end
        end
      end
    end



  end

end
