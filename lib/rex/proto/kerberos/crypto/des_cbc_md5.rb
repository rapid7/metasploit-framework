# -*- coding: binary -*-

require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        class DesCbcMd5 < BlockCipherBase
          include Rex::Proto::Kerberos::Crypto::Asn1Utils

          HASH_LENGTH = 16
          BLOCK_SIZE = 8
          PADDING_SIZE = 8
          MAC_SIZE = 16

          # Derive an encryption key based on a password and salt for the given cipher type
          #
          # @param password [String] The password to use as the basis for key generation
          # @param salt [String] A salt (usually based on domain and username)
          # @param params [String] Unused for this encryption type
          # @return [String] The derived key
          def string_to_key(password, salt, params: nil)
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Params not supported for DES' unless params == nil
            reverse_this_block = false
            tempstring = [0,0,0,0,0,0,0,0]

            utf8_encoded = (password + salt).encode('UTF-8').bytes.pack('C*')

            data = pad_with_zeroes(utf8_encoded, PADDING_SIZE)
            data_as_blocks = data.unpack('C*')

            data_as_blocks.each_slice(BLOCK_SIZE) do |block|
              result = []
              block.each do |byte|
                # Ignore the Most Significant Bit of each byte
                result.append(byte & 0x7F)
              end

              if reverse_this_block
                reversed = []
                result.reverse.each do |byte|
                  d = byte.digits(2)
                  d = d + [0] * (7 - d.length)
                  reversed.append(d.join('').to_i(2))
                end

                result = reversed
              end

              reverse_this_block = (not reverse_this_block)

              tempstring = xor_bytes(tempstring,result)
            end

            paritied = addparity(tempstring)
            tempkey = paritied.pack('C*')

            if _is_weak_des_key(tempkey)
              paritied[7] = paritied[7] ^ 0xF0
              tempkey = paritied.pack('C*')
            end

            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.encrypt
            cipher.padding = 0
            cipher.key = tempkey
            cipher.iv = tempkey

            encrypted = cipher.update(data) + cipher.final
            checksumkey = encrypted

            checksumkey = encrypted[-8,8]
            paritied = fixparity(checksumkey.unpack('C*'))
            checksumkey = paritied.pack('C*')
            if _is_weak_des_key(checksumkey)
              paritied[7] = paritied[7] ^ 0xF0
              checksumkey = paritied.pack('C*')
            end

            checksumkey
          end

          # Decrypts the cipher using DES-CBC-MD5 schema
          #
          # @param ciphertext [String] the data to decrypt
          # @param key [String] the key to decrypt
          # @param msg_type [Integer] ignored for this algorithm
          # @return [String] the decrypted cipher
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosError] if decryption doesn't succeed
          def decrypt(ciphertext, key, msg_type)
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short' unless ciphertext && ciphertext.length > BLOCK_SIZE + HASH_LENGTH
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext is not a multiple of block length' unless ciphertext.length % BLOCK_SIZE == 0


            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.decrypt
            cipher.padding = 0
            cipher.key = key
            decrypted = cipher.update(ciphertext)

            confounder = decrypted[0, BLOCK_SIZE]
            checksum = decrypted[BLOCK_SIZE, HASH_LENGTH]
            plaintext = decrypted[BLOCK_SIZE + HASH_LENGTH, decrypted.length]
            hashed_data = confounder + "\x00" * HASH_LENGTH + plaintext

            hash_fn = OpenSSL::Digest.new('MD5')

            if hash_fn.digest(hashed_data) != checksum
              raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'HMAC integrity error'
            end

            plaintext
          end

          def decrypt_asn1(ciphertext, key, msg_type)
            result = decrypt(ciphertext, key, msg_type)
            padding_removed = truncate_nulls_after_asn1(result)
          end

          # Encrypts the cipher using DES-CBC-MD5 schema
          #
          # @param plaintext [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @param msg_type [Integer] ignored for this algorithm
          # @param confounder [String] Optionally force the confounder to a specific value
          # @return [String] the encrypted data
          def encrypt(plaintext, key, msg_type, confounder: nil)
            confounder = Rex::Text::rand_text(BLOCK_SIZE) if confounder == nil
            padded_data = pad_with_zeroes(plaintext, PADDING_SIZE)
            hashed_data = confounder + "\x00" * HASH_LENGTH + padded_data
            hash_fn = OpenSSL::Digest.new('MD5')
            checksum = hash_fn.digest(hashed_data)

            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Invalid checksum size' unless checksum.length == HASH_LENGTH

            plaintext = confounder + checksum + padded_data

            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.encrypt
            cipher.padding = 0
            cipher.key = key
            encrypted = cipher.update(plaintext) + cipher.final

            encrypted
          end

          #
          # The number of bytes in the encrypted plaintext that precede the actual plaintext
          #
          def header_byte_count
            BLOCK_SIZE
          end

          #
          # The number of bytes in the encrypted plaintext that follow the actual plaintext
          #
          def trailing_byte_count
            MAC_SIZE
          end

          private

          def fixparity(deskey)
            temp = []
            deskey.each do |byte|
              bits = byte.digits(2).reverse
              bits.pop # Ignore the last bit, since it's a parity bit
              add_at_end = (bits.count(1) + 1) % 2
              bits.append(add_at_end)
              parity_fixed = bits.join('').to_i(2)
              temp.append(parity_fixed)
            end

            temp
          end

          def addparity(bytes)
            temp = []
            bytes.each do |byte|
              bits = byte.digits(2).reverse
              to_add = (bits.count(1) + 1) % 2
              result = (byte << 1) + to_add
              temp.append(result & 0xFF)
            end

            temp
          end

          def xor_bytes(l1,l2)
            result = []
            l1.zip(l2).each do |b1,b2|
              if b1 != nil && b2 != nil
                result.append((b1^b2)&0b01111111)
              end
            end

            result
          end
        end
      end
    end
  end
end
