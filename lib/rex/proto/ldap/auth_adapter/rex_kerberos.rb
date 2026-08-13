# frozen_string_literal: true

require 'net/ldap/auth_adapter'
require 'net/ldap/auth_adapter/sasl'
require 'rubyntlm'

module Rex::Proto::LDAP::AuthAdapter
  class RexKerberos < Net::LDAP::AuthAdapter
    def bind(auth)
      kerberos_authenticator = auth[:kerberos_authenticator]
      unless kerberos_authenticator
        raise Net::LDAP::BindingInformationInvalidError, 'Invalid binding information (missing kerberos authenticator)'
      end

      options = {}
      if @connection.socket.respond_to?(:peer_cert)
        options = {
          gss_channel_binding: Rex::Proto::Gss::ChannelBinding.from_tls_cert(
            @connection.socket.peer_cert
          ),
          # when TLS channel binding is in use, disable the sign and seal flags
          gss_flag_confidential: false,
          gss_flag_integrity: false
        }
      end

      kerberos_result = kerberos_authenticator.authenticate(options)
      initial_credential = kerberos_result[:security_blob]
      kerberos_authenticator.trace_protocol_carrier(
        protocol: 'LDAP',
        direction: 'request',
        label: 'LDAP SASL Bind',
        carrier: 'SASL bind request credential',
        field_name: 'initial_credential',
        token: initial_credential
      )

      result = Net::LDAP::AuthAdapter::Sasl.new(@connection).bind(
        method: :sasl,
        mechanism: 'GSS-SPNEGO',
        initial_credential: initial_credential,
        challenge_response: true
      )
      server_sasl_creds = result.result[:serverSaslCreds] if result.respond_to?(:result) && result.result
      kerberos_authenticator.trace_protocol_carrier(
        protocol: 'LDAP',
        direction: 'response',
        label: 'LDAP serverSaslCreds',
        carrier: 'SASL bind response serverSaslCreds',
        field_name: 'serverSaslCreds',
        token: server_sasl_creds
      )

      if auth[:sign_and_seal]
        encryptor = Encryptor.new(kerberos_authenticator)
        encryptor.setup(@connection, kerberos_result, result.result[:serverSaslCreds])
      end

      result
    end
  end
end

Net::LDAP::AuthAdapter.register(:rex_kerberos, Rex::Proto::LDAP::AuthAdapter::RexKerberos)
