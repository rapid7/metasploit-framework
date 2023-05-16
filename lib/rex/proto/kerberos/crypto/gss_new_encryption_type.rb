module Rex
  module Proto
    module Kerberos
      module Crypto
        # The RFC4121 implementation of GSS wrapping (Section 4.2.6.2)
        # which applies to "newer encryption types" (defined as those not
        # in section 1 of RFC4121)
        # This mixin may be included by Encryption providers in Rex::Proto::Kerberos::Crypto
        module GssNewEncryptionType
          GSS_SENT_BY_ACCEPTOR = 1
          GSS_SEALED = 2
          GSS_ACCEPTOR_SUBKEY = 4

          # The length of the GSS header
          GSS_HEADER_LEN = 16

          TOK_ID_GSS_WRAP = 0x0504

          #
          # Encrypt the message, wrapping it in GSS structures
          # @return [String, Integer, Integer] The encrypted data, the length of its header, and the length of padding added to it prior to encryption
          #
          def gss_wrap(plaintext, key, sequence_number, is_initiator, use_acceptor_subkey: true)
            # Handle wrap-around
            sequence_number &= 0xFFFFFFFFFFFFFFFF

            flags = GSS_SEALED
            flags |= GSS_ACCEPTOR_SUBKEY if use_acceptor_subkey

            if is_initiator
              key_usage = Rex::Proto::Kerberos::Crypto::KeyUsage::GSS_INITIATOR_SEAL
            else
              key_usage = Rex::Proto::Kerberos::Crypto::KeyUsage::GSS_ACCEPTOR_SEAL
              flags |= GSS_SENT_BY_ACCEPTOR
            end

            tok_id = TOK_ID_GSS_WRAP
            filler = 0xFF
            ec = calculate_ec(plaintext)
            rrc = calculate_rrc

            # RFC4121, Section 4.2.4
            plaintext_header = [tok_id, flags, filler, 0, 0, sequence_number].pack('nCCnnQ>')

            header = [tok_id, flags, filler, ec, rrc, sequence_number].pack('nCCnnQ>')
            # "x" chosen as the filler based on the Linux implementation of the kerberos client
            # https://salsa.debian.org/debian/krb5/-/blob/0269810b1aec6c554fb746433f045d59fd34ab3a/src/lib/gssapi/krb5/k5sealv3.c#L160
            ec_filler = "x" * ec
            plaintext = plaintext + ec_filler + plaintext_header
            ciphertext = self.encrypt(plaintext, key.value, key_usage)
            rotated = rotate(ciphertext, rrc)

            result = [header + rotated, header_length, ec]
          end

          def gss_unwrap(ciphertext, key, expected_sequence_number, is_initiator, use_acceptor_subkey: true)
            # Handle wrap-around
            sequence_number &= 0xFFFFFFFFFFFFFFFF

            expected_flags = GSS_SEALED
            expected_flags |= GSS_ACCEPTOR_SUBKEY if use_acceptor_subkey

            if is_initiator
              key_usage = Rex::Proto::Kerberos::Crypto::KeyUsage::GSS_ACCEPTOR_SEAL
              expected_flags |= GSS_SENT_BY_ACCEPTOR
            else
              key_usage = Rex::Proto::Kerberos::Crypto::KeyUsage::GSS_INITIATOR_SEAL
            end
            header = ciphertext[0,GSS_HEADER_LEN]
            ciphertext = ciphertext[GSS_HEADER_LEN, ciphertext.length]

            tok_id, flags, filler, ec, rrc, snd_seq = header.unpack('nCCnnQ>')
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Invalid token ID' unless tok_id == TOK_ID_GSS_WRAP
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Invalid filler' unless filler == 0xFF
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Unexpected flags' unless flags == expected_flags
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, "Invalid sequence number (received #{snd_seq}; expected #{expected_sequence_number})" unless expected_sequence_number == snd_seq

            # Could do some sanity checking here of those values
            ciphertext = rotate(ciphertext, -rrc)

            plaintext = self.decrypt(ciphertext, key.value, key_usage)

            plaintext = plaintext[0, plaintext.length - ec - GSS_HEADER_LEN]
          end

          private

          #
          # The number of bytes that we should rotate the ciphertext by, to
          # coerce the checksum and the header that we append at the end to be at
          # the front of the message. How much this rotates is dependent on whether
          # the specific encryption algorithm places the checksum at the start or 
          # the end of the plaintext prior to encryption.
          #
          def calculate_rrc
            GSS_HEADER_LEN + self.trailing_byte_count
          end

          #
          # The number of filler bytes to add into the plaintext prior to encryption.
          # The intention of ec is to ensure that the crypto algorithm itself does not
          # need to add "residue" (padding). This seems to be relevant only to DES, 
          # which leave padding removal as an exercise to the user (AES strips the padding
          # prior to returning it)
          def calculate_ec(plaintext)
            padding_size = self.class::PADDING_SIZE
            if padding_size == 0
              # No padding, so don't need to buffer up to a multiple of the pad length
              0
            else
              (padding_size - (plaintext.length + GSS_HEADER_LEN)) % padding_size
            end
          end

          #
          # Rotate a ciphertext according to RFC4121 Section 4.2.5
          #
          def rotate(ciphertext, rrc)
            rrc = rrc % ciphertext.length
            if rrc == 0
              ciphertext
            else
              ciphertext[-rrc, rrc] + ciphertext[0, ciphertext.length - rrc]
            end
          end
  
          # 
          # The length of the encrypted header portion of the message.
          # This includes information that is part of the encryption process, such as 
          # confounders, padding, and checksums. As a result, it is dependent on the 
          # encyrption algorithm.
          # This is defined in MS-WSMV section 2.2.9.1.1.2.2
          def header_length
            GSS_HEADER_LEN + GSS_HEADER_LEN + self.header_byte_count + self.trailing_byte_count
          end
        end
      end
    end
  end
end
