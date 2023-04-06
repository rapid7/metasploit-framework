module Rex
  module Proto
    module Gss
      module Kerberos
        # 
        # Encrypt messages according to RFC4121 (Kerberos with GSS)
        # Performs wrapping of tokens in the GSS structure, filler bytes, rotation
        # and sequence number tracking and verification. 
        #
        class MessageEncryptor

          # @param [Rex::Proto::Kerberos::Model::EncryptionKey] key The encryption key used to perform encryption and decryption
          # @param [Integer] encrypt_sequence_number The starting sequence number used to encrypt messages
          # @param [Integer] decrypt_sequence_number The starting sequence number we expect to see when we decrypt messages
          # @param [Boolean] is_initiator Are we the initiator in this communication (used for setting flags and key usage values)
          # @param [Boolean] use_acceptor_subkey Are we using the subkey provided by the acceptor? (used for setting appropriate flags)
          def initialize(key, encrypt_sequence_number, decrypt_sequence_number, is_initiator: true, use_acceptor_subkey: true)
            @key = key
            @encrypt_sequence_number = encrypt_sequence_number
            @decrypt_sequence_number = decrypt_sequence_number
            @is_initiator = is_initiator
            @use_acceptor_subkey = use_acceptor_subkey
            @encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(key.type)
          end
  
          #
          # Encrypt the message, wrapping it in GSS structures, and increment the sequence number
          # @return [String, Integer, Integer] The encrypted data, the length of its header, and the length of padding added to it prior to encryption
          #
          def encrypt_and_increment(data)
            result = encryptor.gss_wrap(data, @key, @encrypt_sequence_number, @is_initiator, use_acceptor_subkey: @use_acceptor_subkey)
            @encrypt_sequence_number += 1  
            
            result
          end

          #
          # Decrypt a ciphertext, and verify its validity
          #
          def decrypt_and_verify(data)
            result = encryptor.gss_unwrap(data, @key, @decrypt_sequence_number, @is_initiator, use_acceptor_subkey: @use_acceptor_subkey)
            @decrypt_sequence_number += 1

            result
          end

          #
          # The sequence number to use when we are encrypting, which should be incremented for each message
          #
          attr_accessor :encrypt_sequence_number

          #
          # The sequence number we expect to see after decrypting, which is expected to be incremented for each message
          #
          attr_accessor :decrypt_sequence_number

          #
          # [Rex::Proto::Kerberos::Model::EncryptionKey] The encryption key to use for encryption and decryption
          #
          attr_accessor :key

          #
          # Are we (the encryptor) also the initiator in this interaction (vs being the Acceptor)
          # This refers to the term used in RFC2743/RFC4121
          #
          attr_accessor :is_initiator

          #
          # [Boolean] Whether the acceptor subkey is used for these operations
          #
          attr_accessor :use_acceptor_subkey

          #
          # [Rex::Proto::Kerberos::Crypto::*] Encryption class for encrypting/decrypting messages
          #
          attr_accessor :encryptor
        end
      end
    end
  end
end
