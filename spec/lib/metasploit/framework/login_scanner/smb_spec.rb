require 'spec_helper'
require 'metasploit/framework/login_scanner/smb'

RSpec.describe Metasploit::Framework::LoginScanner::SMB do
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
  it_behaves_like 'Metasploit::Framework::Tcp::Client'

  it { is_expected.to respond_to :smb_chunk_size }
  it { is_expected.to respond_to :smb_name }
  it { is_expected.to respond_to :smb_native_lm }
  it { is_expected.to respond_to :smb_native_os }
  it { is_expected.to respond_to :smb_obscure_trans_pipe_level }
  it { is_expected.to respond_to :smb_pad_data_level }
  it { is_expected.to respond_to :smb_pad_file_level }
  it { is_expected.to respond_to :smb_pipe_evasion }

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
    before(:example) do
      allow(login_scanner).to receive_message_chain(:simple, :client, :auth_user, :nil?).and_return false
    end
    context 'when there is a connection error' do
      it 'returns a result with the connection_error status' do
        allow(login_scanner).to receive_message_chain(:simple, :login).and_raise ::Rex::ConnectionError
        expect(login_scanner.attempt_login(pub_blank).status).to eq Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
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
        it "returns a DENIED_ACCESS status" do
          exception = Rex::Proto::SMB::Exceptions::LoginError.new
          exception.error_code = code

          allow(login_scanner).to receive_message_chain(:simple, :login).and_raise exception
          allow(login_scanner).to receive_message_chain(:simple, :connect)
          allow(login_scanner).to receive_message_chain(:simple, :disconnect)
          allow(login_scanner).to receive_message_chain(:simple, :client, :auth_user, :nil?).and_return false

          expect(login_scanner.attempt_login(pub_blank).status).to eq Metasploit::Model::Login::Status::DENIED_ACCESS
        end
      end

    end

    context 'when the login fails' do
      it 'returns a result object with a status of Metasploit::Model::Login::Status::INCORRECT' do
        allow(login_scanner).to receive_message_chain(:simple, :login).and_return false
        allow(login_scanner).to receive_message_chain(:simple, :connect).and_raise Rex::Proto::SMB::Exceptions::Error
        expect(login_scanner.attempt_login(pub_blank).status).to eq Metasploit::Model::Login::Status::INCORRECT
      end
    end

    context 'when the login succeeds' do
      context 'and the user is local admin' do
        before(:example) do
          login_scanner.simple = double
          allow(login_scanner.simple).to receive(:connect).with(/.*admin\$/i)
          allow(login_scanner.simple).to receive(:connect).with(/.*ipc\$/i)
          allow(login_scanner.simple).to receive(:disconnect)
        end

        it 'returns a result object with a status of Metasploit::Model::Login::Status::SUCCESSFUL' do
          allow(login_scanner).to receive_message_chain(:simple, :login).and_return true
          result = login_scanner.attempt_login(pub_blank)
          expect(result.status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
          expect(result.access_level).to eq described_class::AccessLevels::ADMINISTRATOR
        end
      end

      context 'and the user is NOT local admin' do
        before(:example) do
          login_scanner.simple = double
          allow(login_scanner.simple).to receive(:connect).with(/.*admin\$/i).and_raise(
            # STATUS_ACCESS_DENIED
            Rex::Proto::SMB::Exceptions::ErrorCode.new.tap{|e|e.error_code = 0xC0000022}
          )
          allow(login_scanner.simple).to receive(:connect).with(/.*ipc\$/i)
        end

        it 'returns a result object with a status of Metasploit::Model::Login::Status::SUCCESSFUL' do
          allow(login_scanner).to receive_message_chain(:simple, :login).and_return true
          result = login_scanner.attempt_login(pub_blank)
          expect(result.status).to eq Metasploit::Model::Login::Status::SUCCESSFUL
          expect(result.access_level).to_not eq described_class::AccessLevels::ADMINISTRATOR
        end
      end
    end
  end

end

