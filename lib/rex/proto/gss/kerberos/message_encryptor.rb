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
          # @param [Boolean] dce_style Is the format of the encrypted blob DCE-style?
          def initialize(key, encrypt_sequence_number, decrypt_sequence_number, is_initiator: true, use_acceptor_subkey: true, dce_style: false, rc4_pad_style: :single_byte)
            @key = key
            @encrypt_sequence_number = encrypt_sequence_number
            @decrypt_sequence_number = decrypt_sequence_number
            @is_initiator = is_initiator
            @use_acceptor_subkey = use_acceptor_subkey
            @dce_style = dce_style
            @rc4_pad_style = rc4_pad_style
            @encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(key.type)
          end
  
          #
          # Encrypt the message, wrapping it in GSS structures, and increment the sequence number
          # @return [String, Integer, Integer] The encrypted data, the length of its header, and the length of padding added to it prior to encryption
          #
          def encrypt_and_increment(data)
            result = encryptor.gss_wrap(data, @key, @encrypt_sequence_number, @is_initiator, use_acceptor_subkey: @use_acceptor_subkey, dce_style: @dce_style, rc4_pad_style: @rc4_pad_style)
            @encrypt_sequence_number += 1  
            
            result
          end

          #
          # Decrypt a ciphertext, and verify its validity
          #
          def decrypt_and_verify(data)
            result = encryptor.gss_unwrap(data, @key, @decrypt_sequence_number, @is_initiator, use_acceptor_subkey: @use_acceptor_subkey)
            @decrypt_sequence_number += 1 unless @decrypt_sequence_number.nil?

            result
          end

          def calculate_encrypted_length(plaintext_len)
            encryptor.calculate_encrypted_length(plaintext_len)
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
          # [Boolean] Whether this encryptor will be used for DCERPC purposes (since the behaviour is subtly different)
          # See MS-KILE 3.4.5.4.1 for details about the exception to the rule:
          # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550
          #
          # "For [MS-RPCE], the length field in the above pseudo ASN.1 header does not include the length of the concatenated data if [RFC1964] is used."
          #
          attr_accessor :dce_style

          #
          # [Symbol] The RC4 spec (RFC4757) section 7.3 implies that RC4-HMAC only needs one byte of padding,
          # although it doesn't come straight out and say it. Some protocols (LDAP, at least on a DC) complain
          # if you give it more than a single byte of paddding.
          # Other protocols (DRSR) complain if you don't align it perfectly with an 8-byte boundary.
          # The MS-RPCE spec is a little vague on why exactly that might be, but we can at least
          # show empirically that it is happy if you just give it an 8-byte aligned encrypted stub.
          # Yet other protocols are happy whatever the padding (WinRM).
          # Here, we allow customising the behaviour of the RC4-HMAC GSSAPI crypto scheme by providing either:
          # - :single_byte -> Puts a single '\x01' byte of padding at the end
          # - :eight_byte_aligned -> Puts between 1 and 8 bytes of PKCS#5 padding
          attr_accessor :rc4_pad_style

          #
          # [Rex::Proto::Kerberos::Crypto::*] Encryption class for encrypting/decrypting messages
          #
          attr_accessor :encryptor
        end
      end
    end
  end
end
