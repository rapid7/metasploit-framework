require 'openssl'

module OpenSSL
  # CCMError used for wrong parameter resonse.
  class CCMError < StandardError
  end

  # Abstract from http://tools.ietf.org/html/rfc3610:
  #
  # Counter with CBC-MAC (CCM) is a generic authenticated encryption
  # block cipher mode.  CCM is defined for use with 128-bit block
  # ciphers, such as the Advanced Encryption Standard (AES).
  #
  # At the moment there is no update function, because length of
  # data and additional_data are needed at the begin of cipher process.
  # In future init(nonce, data_len, additional_data_len) could
  # be a solution, to solve this problem. After init, update(data)
  # could be used to set additional_data first followed by data.
  class CCM
    # Searches for supported algorithms within OpenSSL
    #
    # @return [[String]] supported algorithms
    def self.ciphers
      l = OpenSSL::Cipher.ciphers.keep_if { |c| c.end_with?('-128-CBC') or
        c.end_with?('-192-CBC') or c.end_with?('-256-CBC') }
      l.length.times { |i| l[i] = l[i][0..-9] }
      l
    end

    public

    # Creates a new CCM object.
    #
    # @param cipher [String] one of the supported algorithms like 'AES'
    # @param key [String] the key used for encryption and decryption
    # @param mac_len [Number] the length of the mac.
    #        needs to be in 4, 6, 8, 10, 12, 14, 16
    #
    # @return [Object] the new CCM object
    def initialize(cipher, key, mac_len)
      unless CCM.ciphers.include?(cipher)
        fail CCMError, "unsupported cipher algorithm (#{cipher})"
      end
      fail CCMError, 'invalid key length' unless key.b.length >= 16
      unless (4..16).step(2).include?(mac_len)
        fail CCMError, 'invalid mac length'
      end

      if key.length < 24
        cipher_key_size = "128"
      elsif key.length < 32
        cipher_key_size = "192"
      else
        cipher_key_size = "256"
      end

      @cipher = OpenSSL::Cipher.new("#{cipher}-" + cipher_key_size  + "-CBC")
      @key = key
      @mac_len = mac_len
    end

    # Encrypts the input data and appends mac for authentication.
    # If there is additional data, its included into mac calculation.
    #
    # @param data [String] the data to encrypt
    # @param nonce [String] the nonce used for encryption
    # @param additional_data [String] additional data to
    #        authenticate with mac (not part of the output)
    #
    # @return [String] the encrypted data with appended mac
    def encrypt(data, nonce, additional_data = '')
      valid?(data, nonce, additional_data)

      crypt(data, nonce) + mac(data, nonce, additional_data)
    end

    # Decrypts the input data and checks the appended mac.
    # If additional data was used for encryption, its needed
    # for decryption, to check the authentication (mac).
    #
    # @param data [String] the data to decrypt
    # @param nonce [String] the nonce used for decryption
    # @param additional_data [String] additional data to check
    #        authentication (not part of the output)
    #
    # @return [String] the decrypted data without mac
    def decrypt(data, nonce, additional_data = '')
      valid?(data, nonce, additional_data)

      new_data = crypt(data.b[0...-@mac_len], nonce)
      new_mac = mac(new_data, nonce, additional_data)
      return new_data if new_mac == data.b[-@mac_len..-1]
      ''
    end

    private

    def valid?(data, nonce, additional_data)
      unless (7..13).include?(nonce.b.length)
        fail CCMError, 'invalid nonce length'
      end
      unless data.b.length < 2**(8 * (15 - nonce.b.length))
        fail CCMError, 'invalid data length'
      end
      unless additional_data.b.length < 2**64
        fail CCMError, 'invalid additional_data length'
      end
      true
    end

    def crypt(data, nonce)
      result = ''
      data.bytes.each_slice(16).with_index(1) do |block, b|
        counter = get_counter(nonce, b).bytes
        block.length.times { |i| counter[i] ^= block[i] }
        result << counter[0, block.length].pack('C*')
      end
      result
    end

    def mac(data, nonce, additional_data)
      @cipher.reset
      @cipher.encrypt
      @cipher.key = @key

      b_0 = Array.new(8, 0)
      b_0[0] = (additional_data.empty? ? 0 : 64) \
             + (8 * ((@mac_len - 2) / 2)) \
             + (14 - nonce.b.length)
      b_0 += [data.b.length].pack('Q').reverse.bytes
      b_0[1, nonce.b.length] = nonce.bytes
      mac = @cipher.update(b_0.pack('C*')).bytes

      unless additional_data.empty?
        len = additional_data.b.length
        d = case
            when len < (2**16 - 2**8)
              [len].pack('n')
            when len < 2**32
              "\xFF\xFE" + [len].pack('N')
            else
              "\xFF\xFF" + [len].pack('Q').reverse
        end + additional_data
        mac = @cipher.update(d + padding(d)).bytes[-16..-1]
      end

      unless data.empty?
        mac = @cipher.update(data + padding(data)).bytes[-16..-1]
      end

      a_0 = get_counter(nonce, 0).bytes
      16.times { |i| mac[i] ^= a_0[i] }
      mac[0...@mac_len].pack('C*')
    end

    def padding(data)
      return '' if (data.b.length % 16) == 0
      "\x00" * (16 - (data.b.length % 16))
    end

    def get_counter(nonce, index)
      a = Array.new(8, 0)
      a[0] = 14 - nonce.b.length
      a += [index].pack('Q').reverse.bytes
      a[1, nonce.b.length] = nonce.bytes

      @cipher.reset
      @cipher.encrypt
      @cipher.key = @key
      @cipher.update(a.pack('C*'))
    end
  end
end
