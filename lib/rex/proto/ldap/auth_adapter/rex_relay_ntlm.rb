# frozen_string_literal: true

require 'net/ldap/auth_adapter'
require 'net/ldap/auth_adapter/sasl'
require 'rubyntlm'

module Rex::Proto::LDAP::AuthAdapter
  # This implements NTLM authentication but facilitates operation from within a relay context where the NTLM processing
  # is being handled by an external entity (the relay victim) and it expects to be called repeatedly with the necessary
  # NTLM message
  class RexRelayNtlm < Net::LDAP::AuthAdapter
    # @param auth [Hash] the options for binding
    # @option opts [String] :ntlm_message the serialized NTLM message to send to the server, the type does not matter
    def bind(auth)
      mech = 'GSS-SPNEGO'
      ntlm_message = auth[:ntlm_message]
      raise Net::LDAP::BindingInformationInvalidError, "Invalid binding information (invalid NTLM message)" unless ntlm_message

      message_id = @connection.next_msgid
      sasl = [mech.to_ber, ntlm_message.to_ber].to_ber_contextspecific(3)
      request = [
        Net::LDAP::Connection::LdapVersion.to_ber, "".to_ber, sasl
      ].to_ber_appsequence(Net::LDAP::PDU::BindRequest)

      @connection.send(:write, request, nil, message_id)
      pdu = @connection.queued_read(message_id)

      if !pdu || pdu.app_tag != Net::LDAP::PDU::BindResult
        raise Net::LDAP::NoBindResultError, "no bind result"
      end

      pdu
    end
  end
end

Net::LDAP::AuthAdapter.register(:rex_relay_ntlm, Rex::Proto::LDAP::AuthAdapter::RexRelayNtlm)
