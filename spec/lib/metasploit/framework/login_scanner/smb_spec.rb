require 'spec_helper'
require 'metasploit/framework/login_scanner/smb'

describe Metasploit::Framework::LoginScanner::SMB do
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


  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: true
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::NTLM'

  it { should respond_to :smb_chunk_size }
  it { should respond_to :smb_name }
  it { should respond_to :smb_native_lm }
  it { should respond_to :smb_native_os }
  it { should respond_to :smb_obscure_trans_pipe_level }
  it { should respond_to :smb_pad_data_level }
  it { should respond_to :smb_pad_file_level }
  it { should respond_to :smb_pipe_evasion }

  context 'validations' do
    context '#smb_verify_signature' do
      it 'is not valid for the string true' do
        login_scanner.smb_verify_signature = 'true'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:smb_verify_signature]).to include 'is not included in the list'
      end

      it 'is not valid for the string false' do
        login_scanner.smb_verify_signature = 'false'
        expect(login_scanner).to_not be_valid
        expect(login_scanner.errors[:smb_verify_signature]).to include 'is not included in the list'
      end

      it 'is  valid for true class' do
        login_scanner.smb_verify_signature = true
        expect(login_scanner.errors[:smb_verify_signature]).to be_empty
      end

      it 'is  valid for false class' do
        login_scanner.smb_verify_signature = false
        expect(login_scanner.errors[:smb_verify_signature]).to be_empty
      end
    end
  end

  context '#attempt_login' do
    context 'when there is a connection error' do
      it 'returns a result with the connection_error status' do
        login_scanner.stub_chain(:simple, :login).and_raise ::Rex::ConnectionError
        expect(login_scanner.attempt_login(pub_blank).status).to eq :connection_error
      end
    end

    context 'when the credentials are correct, but we cannot login' do
      [
        0xC000006E, # => "STATUS_ACCOUNT_RESTRICTION",
        0xC000006F, # => "STATUS_INVALID_LOGON_HOURS",
        0xC0000070, # => "STATUS_INVALID_WORKSTATION",
        0xC0000071, # => "STATUS_PASSWORD_EXPIRED",
        0xC0000072, # => "STATUS_ACCOUNT_DISABLED",
        0xC000015B, # => "STATUS_LOGON_TYPE_NOT_GRANTED",
        0xC0000193, # => "STATUS_ACCOUNT_EXPIRED",
        0xC0000224, # => "STATUS_PASSWORD_MUST_CHANGE",
      ].each do |code|
        it "returns a status of :correct" do
          exception = Rex::Proto::SMB::Exceptions::ErrorCode.new
          exception.error_code = code

          login_scanner.stub_chain(:simple, :login).and_raise exception

          expect(login_scanner.attempt_login(pub_blank).status).to eq :correct
        end
      end

    end

    context 'when the login fails' do
      it 'returns a result object with a status of :failed' do
        login_scanner.stub_chain(:simple, :login).and_return false
        login_scanner.stub_chain(:simple, :connect)
        expect(login_scanner.attempt_login(pub_blank).status).to eq :failed
      end
    end

    context 'when the login succeeds' do
      it 'returns a result object with a status of :success' do
        login_scanner.stub_chain(:simple, :login).and_return true
        login_scanner.stub_chain(:simple, :connect)
        expect(login_scanner.attempt_login(pub_blank).status).to eq :success
      end
    end
  end

end

