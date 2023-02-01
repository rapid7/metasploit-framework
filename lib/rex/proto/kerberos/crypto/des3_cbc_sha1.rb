# -*- coding: binary -*-
require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        class Des3CbcSha1 < BlockCipherBase
          include Rex::Proto::Kerberos::Crypto::Asn1Utils
          SEED_SIZE = 21
          BLOCK_SIZE = 8
          PADDING_SIZE = 8
          MAC_SIZE = 20
          HASH_FUNCTION = 'SHA1'

          # Derive an encryption key based on a password and salt for the given cipher type
          #
          # @param string [Stringl The password to use as the basis for key generation
          # @param salt [String] A salt (usually based on domain and username)
          # @param params [String] Unused for this encryption type
          # @return [String] The derived key
          def string_to_key(string, salt, params: nil)
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Params not supported for DES' unless params == nil
            utf8_encoded = (string + salt).encode('UTF-8').bytes
            k = random_to_key(nfold(utf8_encoded, 21))
            k = k.pack('C*')
            result = derive(k, 'kerberos'.encode('UTF-8'))

            result
          end

          def decrypt_asn1(ciphertext, key, msg_type)
            result = decrypt(ciphertext, key, msg_type)
            padding_removed = truncate_nulls_after_asn1(result)
          end

          private

          # Decrypts the cipher using DES3-CBC-SHA1 schema
          def decrypt_basic(ciphertext, key)
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext is not a multiple of block length' unless ciphertext.length % BLOCK_SIZE == 0
            cipher = OpenSSL::Cipher.new('des-ede3-cbc')
            cipher.decrypt
            cipher.key = key
            cipher.padding = 0
            decrypted = cipher.update(ciphertext) + cipher.final

            decrypted
          end

          # Encrypts the cipher using DES3-CBC-SHA1 schema
          def encrypt_basic(plaintext, key)
            cipher = OpenSSL::Cipher.new('des-ede3-cbc')
            cipher.encrypt
            cipher.key = key
            cipher.padding = 0
            encrypted = cipher.update(plaintext) + cipher.final

            encrypted
          end

          def random_to_key(seed)
            def expand(seed)
              def parity(b)
                # Return b with the low-order bit set to yield odd parity.
                b &= ~1
                b | (b.digits(2).count(1) + 1) % 2
              end
              
              raise Rex::Proto::Kerberos::Model::Error::KerberosError unless seed.length == 7
        
              firstbytes = seed.map {|b| parity(b & ~1)}
              tmp = 7.times.map { |i| (seed[i] & 1) << i+1 }
              lastbyte = parity(tmp.sum)
              keybytes = firstbytes + [lastbyte]
              if _is_weak_des_key(keybytes)
                keybytes[7] = keybytes[7] ^ 0xF0
              end
              
              keybytes
            end
        
            raise Rex::Proto::Kerberos::Model::Error::KerberosError unless seed.length == 21
            
            subkeys = seed.each_slice(7).map { |slice| expand(slice) }
            subkeys.flatten
          end
        end
      end
    end
  end
end
