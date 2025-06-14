require 'spec_helper'
require 'metasploit/framework/login_scanner/kerberos'
require 'windows_error'
require 'windows_error/nt_status'

RSpec.describe Metasploit::Framework::LoginScanner::Kerberos do
  let(:server_name) { 'demo.local_server' }

  subject(:kerberos_scanner) do
    described_class.new({ server_name: server_name })
  end

  let(:mock_credential) do
    Metasploit::Framework::Credential.new(
      public: 'mock_public',
      private: 'mock_private',
      realm: 'DEMO.LOCAL'
    )
  end

  let(:expected_tgt_request_hmac) do
    {
      server_name: 'demo.local_server',
      client_name: 'mock_public',
      password: 'mock_private',
      realm: 'DEMO.LOCAL',
      offered_etypes: [::Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC]
    }
  end

  let(:expected_tgt_request) do
    {
      server_name: 'demo.local_server',
      client_name: 'mock_public',
      password: 'mock_private',
      realm: 'DEMO.LOCAL'
    }
  end

  let(:tgt_response_no_preauth_required) do
    ::Msf::Exploit::Remote::Kerberos::Model::TgtResponse.new(
      as_rep: instance_double(::Rex::Proto::Kerberos::Model::EncKdcResponse),
      preauth_required: false,
      krb_enc_key: nil,
      decrypted_part: nil
    )
  end

  let(:tgt_response_success) do
    Msf::Exploit::Remote::Kerberos::Model::TgtResponse.new(
      as_rep: instance_double(::Rex::Proto::Kerberos::Model::KdcResponse),
      preauth_required: true,
      krb_enc_key: {
        enctype: Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC,
        key: 'mock-key',
        salt: 'mock-salt'
      },
      decrypted_part: instance_double(::Rex::Proto::Kerberos::Model::EncKdcResponse)
    )
  end

  let(:tgt_response_client_revoked) do
    ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(
      error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED,
      res: ::Rex::Proto::Kerberos::Model::KrbError.new
    )
  end

  let(:tgt_response_client_revoked_locked) do
    err = ::Rex::Proto::Kerberos::Model::KrbError.new
    pwsalt = ::Rex::Proto::Kerberos::Model::PreAuthPwSalt.new
    pwsalt.nt_status = ::WindowsError::NTStatus::STATUS_ACCOUNT_LOCKED_OUT
    pwsalt.flags = 0
    pwsalt.reserved = 0

    padata = ::Rex::Proto::Kerberos::Model::PreAuthDataEntry.new
    padata.type = Rex::Proto::Kerberos::Model::PreAuthType::PA_PW_SALT
    padata.value = pwsalt.encode

    err.e_data = padata.encode

    ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(
      error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED,
      res: err
    )
  end

  let(:tgt_response_account_unknown) do
    ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(
      error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN
    )
  end

  let(:tgt_response_preauth_failed) do
    ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(
      error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_FAILED
    )
  end

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: true, has_default_realm: true

  context '#attempt_login' do
    context 'when the login does not require preauthentication' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_return(tgt_response_no_preauth_required)
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request_hmac).and_return(tgt_response_no_preauth_required)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        # Note: Both correct login and no_preauth_required login attempts will be successful.
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        expect(result.proof).to eq(tgt_response_no_preauth_required)
      end
    end

    context 'when the preauthentication login is successful' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_return(tgt_response_success)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        # Note: Both correct login and no_preauth_required login attempts will be successful.
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        expect(result.proof).to eq(tgt_response_success)
      end
    end

    context 'when the account is disabled' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_raise(tgt_response_client_revoked)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::DISABLED)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED)
      end
    end

    context 'when the account is locked' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_raise(tgt_response_client_revoked_locked)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::LOCKED_OUT)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED)
      end
    end

    context 'when the principal is unknown' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_raise(tgt_response_account_unknown)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::INVALID_PUBLIC_PART)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN)
      end
    end

    context 'when the password is incorrect' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_raise(tgt_response_preauth_failed)
      end

      it 'returns the correct error code' do
        result = subject.attempt_login(mock_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_FAILED)
      end
    end
  end
end
