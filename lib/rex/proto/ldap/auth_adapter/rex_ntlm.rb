# frozen_string_literal: true

require 'net/ldap/auth_adapter'
require 'net/ldap/auth_adapter/sasl'
require 'rubyntlm'

module Rex::Proto::LDAP::AuthAdapter
  class RexNTLM < Net::LDAP::AuthAdapter
    def bind(auth)
      flags = 0 |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:UNICODE] |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:REQUEST_TARGET] |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:NTLM] |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:ALWAYS_SIGN] |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:KEY_EXCHANGE] |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:TARGET_INFO] |
          RubySMB::NTLM::NEGOTIATE_FLAGS[:VERSION_INFO]

      if auth[:sign_and_seal]
        flags = flags |
            RubySMB::NTLM::NEGOTIATE_FLAGS[:SIGN] |
            RubySMB::NTLM::NEGOTIATE_FLAGS[:SEAL] |
            RubySMB::NTLM::NEGOTIATE_FLAGS[:KEY128] |
            RubySMB::NTLM::NEGOTIATE_FLAGS[:KEY56]
      end

      ntlm_client = RubySMB::NTLM::Client.new(
        (auth[:username].nil? ? '' : auth[:username]),
        (auth[:password].nil? ? '' : auth[:password]),
        workstation: 'WORKSTATION',
        domain: auth[:domain].blank? ? '.' : auth[:domain],
        flags: flags
      )

      challenge_response = proc do |challenge|
        challenge.force_encoding(Encoding::BINARY)
        type2_message = Net::NTLM::Message.parse(challenge)
        channel_binding = nil
        if @connection.socket.respond_to?(:peer_cert)
          channel_binding = Rex::Proto::Gss::ChannelBinding.from_tls_cert(@connection.socket.peer_cert)
        end

        type3_message = ntlm_client.init_context(type2_message.encode64, channel_binding)
        type3_message.serialize
      end

      result = Net::LDAP::AuthAdapter::Sasl.new(@connection).bind(
        method: :sasl,
        mechanism: 'GSS-SPNEGO',
        initial_credential: ntlm_client.init_context.serialize,
        challenge_response: challenge_response
      )

      if auth[:sign_and_seal]
        encryptor = Encryptor.new(ntlm_client)
        encryptor.setup(@connection)
      end

      result
    end
  end
end

Net::LDAP::AuthAdapter.register(:rex_ntlm, Rex::Proto::LDAP::AuthAdapter::RexNTLM)
