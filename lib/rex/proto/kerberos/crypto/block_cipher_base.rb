# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        class BlockCipherBase

          # Subclasses must define:
          # BLOCK_SIZE
          # SEED_SIZE
          # PADDING_SIZE
          # HASH_FUNCTION
          # MAC_SIZE
          # decrypt_basic
          # encrypt_basic
          # string_to_key

          # Derive an encryption key based on a password and salt for the given cipher type
          #
          # @param password [String] The password to use as the basis for key generation
          # @param salt [String] A salt (usually based on domain and username)
          # @param params [String] A cipher-specific parameter (currently only used in AES, and even then not usually provided)
          # @return [String] The derived key
          def string_to_key(password, salt, params=nil)
            raise NotImplementedError
          end

          # Use this class's encryption routines to create a checksum of the data based on the key and message type
          #
          # @param key [String] the key to use to generate the checksum
          # @param msg_type [Integer] type of kerberos method in use
          # @param data [String] the data to checksum
          # @return [String] the generated checksum
          def checksum(key, msg_type, data)
            kc = derive(key, [msg_type, 0x99].pack('NC'))
            hmac = OpenSSL::HMAC.digest(self.class::HASH_FUNCTION, kc, data)

            hmac[0, self.class::MAC_SIZE]
          end

          # Decrypts the cipher
          #
          # @param ciphertext_and_mac [String] the data to decrypt
          # @param key [String] the key to decrypt
          # @param msg_type [Integer] type of kerberos message
          # @return [String] the decrypted cipher
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosError] if decryption doesn't succeed
          def decrypt(ciphertext_and_mac, key, msg_type)
            ki = derive(key, [msg_type, 0x55].pack('NC'))
            ke = derive(key, [msg_type, 0xAA].pack('NC'))

            raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short' if ciphertext_and_mac.length < (self.class::BLOCK_SIZE + self.class::MAC_SIZE)

            ciphertext = ciphertext_and_mac.slice(0..-(self.class::MAC_SIZE+1))
            mac = ciphertext_and_mac[-self.class::MAC_SIZE, self.class::MAC_SIZE]


            plaintext = decrypt_basic(ciphertext, ke)
            hmac = OpenSSL::HMAC.digest(self.class::HASH_FUNCTION, ki, plaintext)
            hmac_subset = hmac[0, self.class::MAC_SIZE]
            if mac != hmac_subset
                raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'HMAC integrity error'
            end

            # Discard the confounder.
            plaintext[self.class::BLOCK_SIZE, plaintext.length]
          end

          # Some ciphers add padding and leave it up to the application layer to remove
          # them. In kerberos, this seems to be reliably done by respecting the expected
          # length of the ASN1 structure.
          # For ciphers that remove padding themselves, this just does basic decryption
          alias decrypt_asn1 decrypt

          # Encrypts the cipher
          #
          # @param plaintext [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @param msg_type [Integer] type of kerberos message
          # @param confounder [String] Optionally force the confounder to a specific value
          # @return [String] the encrypted data
          def encrypt(plaintext, key, msg_type, confounder: nil)
            ki = derive(key, [msg_type, 0x55].pack('NC'))
            ke = derive(key, [msg_type, 0xAA].pack('NC'))
            confounder = Rex::Text::rand_text(self.class::BLOCK_SIZE) if confounder == nil
            plaintext = confounder + pad_with_zeroes(plaintext, self.class::PADDING_SIZE)
            hmac = OpenSSL::HMAC.digest(self.class::HASH_FUNCTION, ki, plaintext)

            encrypt_basic(plaintext, ke) + hmac[0,self.class::MAC_SIZE]
          end

          def gss_wrap(plaintext, key, sequence_number, is_initiator, use_acceptor_subkey: true)
            raise NotImplementedError
          end

          def gss_unwrap(ciphertext, key, expected_sequence_number, is_initiator, use_acceptor_subkey: true)
            raise NotImplementedError
          end

          private

          # Functions must be overridden by subclasses:

          def decrypt_basic(cipher, key)
            raise NotImplementedError
          end

          def encrypt_basic(data, key)
            raise NotImplementedError
          end

          # Functions may be overriden by subclasses:
          def random_to_key(seed)
            if seed.length != self.class::SEED_SIZE
              raise Rex::Proto::Kerberos::Model::Error::KerberosError, 'Invalid seed size'
            end

            seed
          end
                    

          # Functions used by subclasses

          # Pads the provided data to a multiple of block_length
          # Zeroes are added at the end
          def pad_with_zeroes(data, padding_size)
            pad_length = padding_size - (data.length % padding_size)
            pad_length %= padding_size # In case it's a perfect multiple, do no padding
            return data + "\x00" * pad_length
          end
          
          def nfold(ba, nbytes)
            # Convert bytearray to a string of length nbytes using the RFC 3961 nfold
            # operation.
          
            # Rotate the bytes in ba to the right by nbits bits.
            def rotate_right(ba, nbits)
              nbytes, remain = (nbits / 8) % ba.length, nbits % 8
              ba.length.times.map do |i|
                (ba[i-nbytes] >> remain) | ((ba[i-nbytes-1] << (8-remain)) & 0xff)
              end
            end
          
            # Add equal-length strings together with end-around carry.
            def add_ones_complement(arr1, arr2)
              n = arr1.length
              # Add all pairs of numbers
              v = arr1.zip(arr2).map { |a,b| a+b}
              
              while v.any? { |x| x > 0xff }
                v = v.length.times.map {|i| (v[i-n+1]>>8) + (v[i]&0xff)}
              end
          
              v
            end
          
            # Let's work in terms of numbers rather than strings
            slen = ba.length
            lcm = nbytes * slen / nbytes.gcd(slen)
            bigstr = []
            num_copies = lcm / slen
            num_copies.times do |i|
              bigstr += rotate_right(ba, 13 * i)
            end
            
            result = bigstr.each_slice(nbytes).reduce {|l1,l2| add_ones_complement(l1,l2) }

            result
          end

          def derive(key_str, constant_str)
            # RFC 3961 only says to n-fold the constant only if it is
            # shorter than the cipher block size.  But all Unix
            # implementations n-fold constants if their length is larger
            # than the block size as well, and n-folding when the length
            # is equal to the block size is a no-op.
            constant_arr = constant_str.bytes
            plaintext_arr = nfold(constant_arr, self.class::BLOCK_SIZE)
            rndseed = []
            while rndseed.length < self.class::SEED_SIZE do
              plaintext_str = plaintext_arr.pack('C*')
              ciphertext_str = encrypt_basic(plaintext_str, key_str)
              ciphertext_arr = ciphertext_str.unpack('C*')
              rndseed += ciphertext_arr
              plaintext_arr = ciphertext_arr
            end

            result = random_to_key(rndseed[0,self.class::SEED_SIZE])

            result.pack('C*')
          end

          def _is_weak_des_key(keybytes)
            ["\x01\x01\x01\x01\x01\x01\x01\x01",
             "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
             "\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E",
             "\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
             "\x01\xFE\x01\xFE\x01\xFE\x01\xFE",
             "\xFE\x01\xFE\x01\xFE\x01\xFE\x01",
             "\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1",
             "\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E",
             "\x01\xE0\x01\xE0\x01\xF1\x01\xF1",
             "\xE0\x01\xE0\x01\xF1\x01\xF1\x01",
             "\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE",
             "\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E",
             "\x01\x1F\x01\x1F\x01\x0E\x01\x0E",
             "\x1F\x01\x1F\x01\x0E\x01\x0E\x01",
             "\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE",
             "\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1"].include?(keybytes)
          end
        end
      end
    end
  end
end
