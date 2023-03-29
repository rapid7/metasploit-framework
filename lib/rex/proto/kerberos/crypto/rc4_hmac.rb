# -*- coding: binary -*-

require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        class Rc4Hmac
          include Rex::Proto::Kerberos::Crypto::Utils
          include Rex::Proto::Gss::Asn1
          MAC_SIZE = 16
          CONFOUNDER_SIZE = 8
          PADDING_SIZE = 1

          # Derive an encryption key based on a password and salt for the given cipher type
          #
          # @param password [String] The password to use as the basis for key generation
          # @param salt [String] Ignored for this encryption algorithm
          # @param params [String] Unused for this encryption type
          # @return [String] The derived key
          def string_to_key(password, salt=nil, params: nil)
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Params not supported for RC4_HMAC' unless params == nil

            unicode_password = password.encode('utf-16le')
            password_digest = OpenSSL::Digest.digest('MD4', unicode_password)
          end
          
          # Use this class's encryption routines to create a checksum of the data based on the key and message type
          #
          # @param key [String] the key to use to generate the checksum
          # @param msg_type [Integer] type of kerberos message
          # @param data [String] the data to checksum
          # @return [String] the generated checksum
          def checksum(key, msg_type, data)
            ksign = OpenSSL::HMAC.digest('MD5', key, "signaturekey\x00")
            md5_hash = Rex::Text.md5_raw(usage_str(msg_type) + data)

            ksign = OpenSSL::HMAC.digest('MD5', ksign, md5_hash)
          end

          # Decrypts the cipher using RC4-HMAC schema
          # https://datatracker.ietf.org/doc/rfc4757/
          #
          # @param ciphertext [String] the data to decrypt
          # @param key [String] the key to decrypt
          # @param msg_type [Integer] type of kerberos message
          # @return [String] the decrypted cipher
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosError] if decryption doesn't succeed
          def decrypt(ciphertext, key, msg_type)
            unless ciphertext && ciphertext.length > MAC_SIZE
              raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'RC4-HMAC decryption failed'
            end

            checksum = ciphertext[0, MAC_SIZE]
            data = ciphertext[MAC_SIZE, ciphertext.length - 1]

            k1 = OpenSSL::HMAC.digest('MD5', key, usage_str(msg_type))
            k3 = OpenSSL::HMAC.digest('MD5', k1, checksum)

            cipher = OpenSSL::Cipher.new('rc4')
            cipher.decrypt
            cipher.key = k3
            decrypted = cipher.update(data) + cipher.final

            if OpenSSL::HMAC.digest('MD5', k1, decrypted) != checksum
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosError, 'RC4-HMAC decryption failed, incorrect checksum verification'
            end

            # Expect the first CONFOUNDER_SIZE bytes to be the confounder
            raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'EncryptedData failed to decrypt' if decrypted.length < CONFOUNDER_SIZE

            # Skip the confounder when returning
            decrypted[CONFOUNDER_SIZE,decrypted.length]
          end

          alias decrypt_asn1 decrypt

          # Encrypts the cipher using RC4-HMAC schema
          # https://datatracker.ietf.org/doc/rfc4757/
          #
          # @param plaintext [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @param msg_type [Integer] type of kerberos message
          # @param confounder [String] Optionally force the confounder to a specific value
          # @return [String] the encrypted data
          def encrypt(plaintext, key, msg_type, confounder: nil)
            k1 = OpenSSL::HMAC.digest('MD5', key, usage_str(msg_type))

            confounder = Rex::Text::rand_text(CONFOUNDER_SIZE) if confounder == nil
            data_encrypt = confounder + plaintext

            checksum = OpenSSL::HMAC.digest('MD5', k1, data_encrypt)

            k3 = OpenSSL::HMAC.digest('MD5', k1, checksum)

            cipher = OpenSSL::Cipher.new('rc4')
            cipher.encrypt
            cipher.key = k3
            encrypted = cipher.update(data_encrypt) + cipher.final

            res = checksum + encrypted
            res
          end

          def gss_unwrap(ciphertext, key, expected_sequence_number, is_initiator, use_acceptor_subkey: true)
            # Always 32-bit sequence number
            expected_sequence_number &= 0xFFFFFFFF

            mech_id, ciphertext = unwrap_pseudo_asn1(ciphertext)

            raise Rex::Proto::Kerberos::Model::Error::KerberosError unless ciphertext.length > 0x20
            header = ciphertext[0,8]
            tok_id, alg, seal_alg, filler = header.unpack('nnnn')
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, "Invalid token id: #{tok_id}" unless tok_id == 0x0201
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, "Invalid alg: #{alg}" unless alg == 0x1100
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, "Invalid seal_alg: #{seal_alg}" unless seal_alg == 0x1000
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, "Invalid filler: #{filler}" unless filler == 0xFFFF

            encrypted_sequence_num = ciphertext[8,8]
            eight_checksum_bytes = ciphertext[16,8]
            encrypted_confounder = ciphertext[24,8]
            emessage = ciphertext[32, ciphertext.length - 32]

            kseq = OpenSSL::HMAC.digest('MD5', key.value, [0].pack('V'))

            kseq = OpenSSL::HMAC.digest('MD5', kseq, eight_checksum_bytes)

            cipher_seq = OpenSSL::Cipher.new('rc4')
            cipher_seq.decrypt
            cipher_seq.key = kseq

            decrypted_sequence_num = cipher_seq.update(encrypted_sequence_num)
            decrypted_sequence_num = decrypted_sequence_num.unpack('N')[0]

            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Invalid sequence number' unless decrypted_sequence_num == expected_sequence_number

            klocal = xor_strings(key.value, "\xF0"*16)
            kcrypt = OpenSSL::HMAC.digest('MD5', klocal, [0].pack('V'))

            # Salt it with the sequence number
            kcrypt = OpenSSL::HMAC.digest('MD5', kcrypt, [decrypted_sequence_num].pack('N'))

            cipher = OpenSSL::Cipher.new('rc4')
            cipher.encrypt
            cipher.key = kcrypt
            decrypted_confounder = cipher.update(encrypted_confounder)

            plaintext = cipher.update(emessage)

            chksum_input = usage_str(Rex::Proto::Kerberos::Crypto::KeyUsage::KRB_PRIV_ENCPART) + header + decrypted_confounder
            ksign = OpenSSL::HMAC.digest('MD5', key.value, "signaturekey\x00")
            sgn_cksum = Rex::Text.md5_raw(chksum_input+plaintext)
            sgn_cksum = OpenSSL::HMAC.digest('MD5', ksign, sgn_cksum)

            verification_eight_checksum_bytes = sgn_cksum[0,8]
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Checksum error' unless verification_eight_checksum_bytes == eight_checksum_bytes

            # Remove padding, if present (seems MS may not send it back?)
            pad_char = plaintext[-1]
            if pad_char == "\x01"
              plaintext = plaintext[0, plaintext.length-1]
            end

            plaintext
          end

          def gss_wrap(plaintext, key, sequence_number, is_initiator, use_acceptor_subkey: true)
            # Always 32-bit sequence number
            sequence_number &= 0xFFFFFFFF

            # Header
            tok_id = 0x0201
            alg = 0x1100
            seal_alg = 0x1000
            filler = 0xFFFF
            header = [tok_id, alg, seal_alg, filler].pack('nnnn')
            # Add a byte of padding (see RFC1964 section 1.2.2.3) 
            plaintext += "\x01"

            send_seq = [sequence_number].pack('N')
            # See errata on RFC4757
            initiator_bytes = "\xFF" * 4
            initiator_bytes = "\x00" * 4 if is_initiator
            send_seq += initiator_bytes

            confounder = Rex::Text::rand_text(CONFOUNDER_SIZE)
            #confounder = ['cd85a6ad14bcf4a4'].pack('H*')
            chksum_input = usage_str(Rex::Proto::Kerberos::Crypto::KeyUsage::KRB_PRIV_ENCPART) + header + confounder
            ksign = OpenSSL::HMAC.digest('MD5', key.value, "signaturekey\x00")
            sgn_cksum = Rex::Text.md5_raw(chksum_input+plaintext)

            klocal = xor_strings(key.value, "\xF0"*16)
            kcrypt = OpenSSL::HMAC.digest('MD5', klocal, [0].pack('V'))

            # Salt it with the sequence number
            kcrypt = OpenSSL::HMAC.digest('MD5', kcrypt, [sequence_number].pack('N'))

            cipher = OpenSSL::Cipher.new('rc4')
            cipher.encrypt
            cipher.key = kcrypt
            encrypted_confounder = cipher.update(confounder)

            encrypted = cipher.update(plaintext)

            sgn_cksum = OpenSSL::HMAC.digest('MD5', ksign, sgn_cksum)
            eight_checksum_bytes = sgn_cksum[0,8]

            kseq = OpenSSL::HMAC.digest('MD5', key.value, [0].pack('V'))

            kseq = OpenSSL::HMAC.digest('MD5', kseq, eight_checksum_bytes)

            cipher_seq = OpenSSL::Cipher.new('rc4')
            cipher_seq.encrypt
            cipher_seq.key = kseq

            encrypted_sequence_num = cipher_seq.update(send_seq)

            token = header + encrypted_sequence_num + eight_checksum_bytes + encrypted_confounder
            size_prior = (token+encrypted).length

            wrapped_token = wrap_pseudo_asn1(
                ::Rex::Proto::Gss::OID_KERBEROS_5,
                token + encrypted
            )
            asn1_length = wrapped_token.length - size_prior
            token_length = asn1_length + token.length

            [wrapped_token, token_length, 0x01]
          end

          #
          # The number of bytes in the encrypted plaintext that precede the actual plaintext
          #
          def header_byte_count
            MAC_SIZE + CONFOUNDER_SIZE
          end

          #
          # The number of bytes in the encrypted plaintext that follow the actual plaintext
          #
          def trailing_byte_count
            0
          end

          private

          def usage_str(msg_type)
            usage_table = {
              Rex::Proto::Kerberos::Crypto::KeyUsage::AS_REP_ENCPART => Rex::Proto::Kerberos::Crypto::KeyUsage::TGS_REP_ENCPART_SESSION_KEY, 
              Rex::Proto::Kerberos::Crypto::KeyUsage::GSS_ACCEPTOR_SIGN => Rex::Proto::Kerberos::Crypto::KeyUsage::KRB_PRIV_ENCPART
            }
            usage_mapped = usage_table.fetch(msg_type) { msg_type }
            [usage_mapped].pack('V')
          end
        end
      end
    end
  end
end
