# frozen_string_literal: true

require 'rex/proto/ldap/auth_adapter'

module Rex::Proto::LDAP::AuthAdapter
  class RexNTLM < Net::LDAP::AuthAdapter

    # Provide the ability to "wrap" LDAP comms in an NTLM encryption routine
    # The methods herein are set up with the auth_context_setup call below,
    # and are called when reading or writing needs to occur.
    class Encryptor
      def initialize(ntlm_client)
        self.ntlm_client = ntlm_client
      end

      # Configure our encryption, and tell the LDAP connection object that we now want to intercept its calls
      # to read and write
      # @param ldap_connection [Net::LDAP::Connection]
      def setup(ldap_connection)
        ldap_connection.wrap_read_write(self.method(:read), self.method(:write))
      end

      # Decrypt the provided ciphertext
      # @param ciphertext [String]
      def read(ciphertext)
        if (session = ntlm_client.session).nil?
          raise Rex::Proto::LDAP::LdapException.new('Can not unseal data (no NTLM session is established)')
        end

        message = session.unseal_message(ciphertext[16..-1])
        unless session.verify_signature(ciphertext[0..15], message)
          raise Rex::Proto::LDAP::LdapException.new('Received invalid message (NTLM signature verification failed)')
        end

        return message
      end

      # Encrypt the provided plaintext
      # @param data [String]
      def write(data)
        if (session = ntlm_client.session).nil?
          raise Rex::Proto::LDAP::LdapException.new('Can not seal data (no NTLM session is established)')
        end

        emessage = session.seal_message(data)
        signature = session.sign_message(data)

        signature + emessage
      end

      attr_accessor :ntlm_client
    end
  end
end
