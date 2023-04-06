# -*- coding: binary -*-
require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        # Base class for RFC3962 AES encryption classes
        class AesBlockCipherBase < BlockCipherBase
          include Rex::Proto::Kerberos::Crypto::Utils
          include Rex::Proto::Kerberos::Crypto::GssNewEncryptionType

          BLOCK_SIZE = 16
          PADDING_SIZE = 1
          MAC_SIZE = 12
          HASH_FUNCTION = 'SHA1'

          # Subclasses must also define ENCRYPT_CIPHER_NAME and DECRYPT_CIPHER_NAME
      
          # Derive an encryption key based on a password and salt for the given cipher type
          #
          # @param password [String] The password to use as the basis for key generation
          # @param salt [String] A salt (usually based on domain and username)
          # @param params [String] When unpacked, the number of iterations used during key generation
          # @return [String] The derived key
          def string_to_key(password, salt, params: nil)
            params = "\x00\x00\x10\x00" if params == nil
            iterations = params.unpack('N')[0]
            seed = OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: iterations, length: self.class::SEED_SIZE, hash: HASH_FUNCTION)
            tkey = random_to_key(seed)
            derive(tkey, 'kerberos'.encode('utf-8'))
          end
      
          def encrypt_basic(plaintext, key)
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short' if plaintext.length < BLOCK_SIZE

            cipher = OpenSSL::Cipher.new(self.class::ENCRYPT_CIPHER_NAME)
            cipher.encrypt
            cipher.key = key
            cipher.padding = 0

            padded = pad_with_zeroes(plaintext, BLOCK_SIZE)
            ciphertext = cipher.update(padded) + cipher.final
            if plaintext.length > BLOCK_SIZE
              # Swap the last two ciphertext blocks and truncate the
              # final block to match the plaintext length.
              last_block_length = plaintext.length % BLOCK_SIZE
              last_block_length = BLOCK_SIZE if last_block_length == 0
              ciphertext = ciphertext[0, ciphertext.length - 32] + ciphertext[-BLOCK_SIZE, BLOCK_SIZE] + ciphertext[-32, last_block_length]
            end

            ciphertext
          end
      
          def decrypt_basic(ciphertext, key)
            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short' if ciphertext.length < BLOCK_SIZE

            cipher = OpenSSL::Cipher.new(self.class::DECRYPT_CIPHER_NAME)
            cipher.decrypt
            cipher.key = key
            cipher.padding = 0

            if ciphertext.length == BLOCK_SIZE
              return cipher.update(ciphertext) + cipher.final
            end

            # Split the ciphertext into blocks.  The last block may be partial.
            block_chunks = ciphertext.unpack('C*').each_slice(BLOCK_SIZE).to_a
            last_block_length = block_chunks[-1].length

            # CBC-decrypt all but the last two blocks.
            prev_chunk = [0] * BLOCK_SIZE
            plaintext_arr = []
            block_chunks.slice(0..-3).each do |chunk|
              decrypted = cipher.update(chunk.pack('C*')) + cipher.final
              decrypted_arr = decrypted.unpack('C*')
              plaintext_arr += xor_bytes(decrypted_arr, prev_chunk)
              prev_chunk = chunk
            end

            # Decrypt the second-to-last cipher block.  The left side of
            # the decrypted block will be the final block of plaintext
            # xor'd with the final partial cipher block; the right side
            # will be the omitted bytes of ciphertext from the final
            # block.
            decrypted = cipher.update(block_chunks[-2].pack('C*')) + cipher.final
            decrypted_arr = decrypted.unpack('C*')
            last_plaintext_arr = xor_bytes(decrypted_arr[0, last_block_length], block_chunks[-1])
            omitted_arr = decrypted_arr[last_block_length, decrypted.length]

            # Decrypt the final cipher block plus the omitted bytes to get
            # the second-to-last plaintext block.

            decrypted = cipher.update((block_chunks[-1] + omitted_arr).pack('C*'))
            decrypted_arr = decrypted.unpack('C*')
            plaintext_arr += xor_bytes(decrypted_arr, prev_chunk)
            (plaintext_arr + last_plaintext_arr).pack('C*')
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
        end
      end
    end
  end
end
