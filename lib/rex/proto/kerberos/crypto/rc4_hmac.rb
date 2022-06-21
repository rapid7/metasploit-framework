# -*- coding: binary -*-

require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        class Rc4Hmac

          # Derive an encryption key based on a password and salt for the given cipher type
          #
          # @param password [String] The password to use as the basis for key generation
          # @param salt [String] A salt (usually based on domain and username)
          # @param iterations [Integer] Unused for this encryption type
          # @return [String] The derived key
          def string_to_key(password, salt=nil, iterations=nil)
            raise ::RuntimeError, 'Iterations not supported for DES3' unless iterations == nil
            raise ::RuntimeError, 'Salt not supported for DES3' unless iterations == nil
            # Salt is unused in Rc4
            unicode_password = Rex::Text.to_unicode(password)
            password_digest = OpenSSL::Digest.digest('MD4', unicode_password)

            password_digest
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
            unless ciphertext && ciphertext.length > 16
              raise ::RuntimeError, 'RC4-HMAC decryption failed'
            end

            checksum = ciphertext[0, 16]
            data = ciphertext[16, ciphertext.length - 1]

            k1 = OpenSSL::HMAC.digest('MD5', key, usage_str(msg_type))
            k3 = OpenSSL::HMAC.digest('MD5', k1, checksum)

            cipher = OpenSSL::Cipher.new('rc4')
            cipher.decrypt
            cipher.key = k3
            decrypted = cipher.update(data) + cipher.final

            if OpenSSL::HMAC.digest('MD5', k1, decrypted) != checksum
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosError, 'RC4-HMAC decryption failed, incorrect checksum verification'
            end

            # Expect the first 8 bytes to be the confounder
            raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'EncryptedData failed to decrypt' if decrypted.length < 8

            # Skip the confounder when returning
            decrypted[8,decrypted.length]
          end

          # Encrypts the cipher using RC4-HMAC schema
          # https://datatracker.ietf.org/doc/rfc4757/
          #
          # @param plaintext [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @param msg_type [Integer] type of kerberos message
          # @param confounder [String] Optionally force the confounder to a specific value
          # @return [String] the encrypted data
          def encrypt(plaintext, key, msg_type, confounder=nil)
            k1 = OpenSSL::HMAC.digest('MD5', key, usage_str(msg_type))

            confounder = Rex::Text::rand_text(8) if confounder == nil
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

          private

          def usage_str(msg_type)
            usage_table = { 3 => 8, 23 => 13 }
            usage_mapped = usage_table.fetch(msg_type) { msg_type }
            [usage_mapped].pack('V')
          end
        end
      end
    end
  end
end
