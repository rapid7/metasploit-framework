# frozen_string_literal: true

module Metasploit
  module Framework
    module LDAP

      # Provide the ability to "wrap" LDAP comms in a Kerberos encryption routine
      # The methods herein are set up with the auth_context_setup call below,
      # and are called when reading or writing needs to occur.
      class SpnegoKerberosEncryptor
        include Rex::Proto::Gss::Asn1
        # @param kerberos_authenticator [Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base] Kerberos authenticator
        def initialize(kerberos_authenticator)
          self.kerberos_authenticator = kerberos_authenticator
        end

        # The AP-REQ to send to the server
        def get_initial_credential
          self.kerberos_result = self.kerberos_authenticator.authenticate
          self.kerberos_result[:security_blob]
        end

        # Configure our encryption, and tell the LDAP connection object that we now want to intercept its calls
        # to read and write
        # @param gssapi_response [String,nil] GSS token containing the AP-REP from the server if mutual auth was used, or nil otherwise
        # @param ldap_connection [Net::LDAP::Connection]
        def kerberos_setup(gssapi_response, ldap_connection)
          spnego = Rex::Proto::Gss::SpnegoNegTokenTarg.parse(gssapi_response)
          if spnego.response_token.nil?
            # No mutual auth result
            self.kerberos_encryptor = kerberos_authenticator.get_message_encryptor(self.kerberos_result[:session_key],
                                                                                   self.kerberos_result[:client_sequence_number],
                                                                                   nil,
                                                                                   use_acceptor_subkey: false)
          else
            mutual_auth_result = self.kerberos_authenticator.parse_gss_init_response(spnego.response_token, self.kerberos_result[:session_key])
            self.kerberos_encryptor = kerberos_authenticator.get_message_encryptor(mutual_auth_result[:ap_rep_subkey],
                                                                                   self.kerberos_result[:client_sequence_number],
                                                                                   mutual_auth_result[:server_sequence_number],
                                                                                   use_acceptor_subkey: true)
          end
          ldap_connection.wrap_read_write(self.method(:read), self.method(:write))
        end

        # Decrypt the provided ciphertext
        # @param ciphertext [String]
        def read(ciphertext)
          begin
            plaintext = self.kerberos_encryptor.decrypt_and_verify(ciphertext)
          rescue Rex::Proto::Kerberos::Model::Error::KerberosError => exception
            raise Rex::Proto::LDAP::LdapException.new('Received invalid Kerberos message')
          end
          return plaintext
        end

        # Encrypt the provided plaintext
        # @param data [String]
        def write(data)
          emessage, header_length, pad_length = self.kerberos_encryptor.encrypt_and_increment(data)

          emessage
        end

        attr_accessor :kerberos_encryptor
        attr_accessor :kerberos_authenticator
        attr_accessor :kerberos_result
      end
    end
  end
end
