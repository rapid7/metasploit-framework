# -*- coding: binary -*-

module Rex
  module Crypto
    class Chacha20
      attr_reader :chacha_ctx

      def initialize(key, iv)
        raise TypeError unless key.is_a? String
        raise TypeError unless iv.is_a? String

        @chacha_ctx = chacha20_ctx_setup(key, iv)
      end

      def reset_cipher(key, iv)
        @chacha_ctx = chacha20_ctx_setup(key, iv)
      end

      def chacha20_update_ctx
        @chacha_ctx[12] = (@chacha_ctx[12] + 1) & 0xffffffff
      end

      def chacha20_ctx_setup(key, iv, position=1)
        chacha_constants = [1634760805, 857760878, 2036477234, 1797285236]
        chacha_ctx = chacha_constants

        chacha_ctx += key.unpack('V8')
        chacha_ctx[12] = position
        chacha_ctx += iv.unpack('VVV')

        chacha_ctx
      end

      def chacha20_crypt(data)
        num_blocks = data.length / 64
        if data.length % 64 != 0
         num_blocks += 1
        end

        keystream = []
        (1..num_blocks).each do |block|
          keystream << chacha20_block_func
          chacha20_update_ctx
        end
        keystream = keystream.flatten

        enc = []
        i = 0
        data.unpack("c*").each do |a|
          enc << (a.ord ^ keystream[i])
          i += 1
        end
        enc.pack("c*").force_encoding('ASCII-8BIT')
      end

      def chacha20_block_func
        chacha_state = @chacha_ctx.dup

        (1..10).each do |round|
          quarter_round(chacha_state, 0, 4, 8, 12)
          quarter_round(chacha_state, 1, 5, 9, 13)
          quarter_round(chacha_state, 2, 6, 10, 14)
          quarter_round(chacha_state, 3, 7, 11, 15)
          quarter_round(chacha_state, 0, 5, 10, 15)
          quarter_round(chacha_state, 1, 6, 11, 12)
          quarter_round(chacha_state, 2, 7, 8, 13)
          quarter_round(chacha_state, 3, 4, 9, 14)
        end

        keystream_arr = []
        (0..15).each do |index|
          keystream_ch = (chacha_state[index] + @chacha_ctx[index]) & 0xffffffff
          keystream_arr << (keystream_ch & 0xff)
          keystream_arr << (keystream_ch >> 8 & 0xff)
          keystream_arr << (keystream_ch >> 16 & 0xff)
          keystream_arr << (keystream_ch >> 24 & 0xff)
        end

        keystream_arr
      end

      def rotate(v, c)
        ((v << c) & 0xffffffff) | v >> (32 - c)
      end

      def quarter_round(x, a, b, c, d)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 7)
      end
    end
=begin
    def self.chacha20_xor_stream(key, iv, position = 1)
      # Generate the xor stream with the ChaCha20 cipher

      raise TypeError unless position.is_a? Integer
      raise TypeError unless key.is_a? String
      raise TypeError unless iv.is_a? String
      raise RangeError.new("position > uint32") if position > 0xffffffff
      raise RangeError.new("key.length != 32") unless key.length == 32
      raise RangeError.new("iv.length != 12 (#{iv.length})") unless iv.length == 12

      Enumerator.new do |enum|
        def self.rotate(v, c)
          ((v << c) & 0xffffffff) | v >> (32 - c)
        end

        def self.quarter_round(x, a, b, c, d)
          x[a] = (x[a] + x[b]) & 0xffffffff
          x[d] = rotate(x[d] ^ x[a], 16)
          x[c] = (x[c] + x[d]) & 0xffffffff
          x[b] = rotate(x[b] ^ x[c], 12)
          x[a] = (x[a] + x[b]) & 0xffffffff
          x[d] = rotate(x[d] ^ x[a], 8)
          x[c] = (x[c] + x[d]) & 0xffffffff
          x[b] = rotate(x[b] ^ x[c], 7)
        end

        ctx = [1634760805, 857760878, 2036477234, 1797285236]
        ctx += key.unpack('V8')
        ctx[12] = position
        ctx += iv.unpack('VVV')
        while true
          x = ctx.dup
          for i in 0..9
            quarter_round(x, 0, 4,  8, 12)
            quarter_round(x, 1, 5,  9, 13)
            quarter_round(x, 2, 6, 10, 14)
            quarter_round(x, 3, 7, 11, 15)
            quarter_round(x, 0, 5, 10, 15)
            quarter_round(x, 1, 6, 11, 12)
            quarter_round(x, 2, 7,  8, 13)
            quarter_round(x, 3, 4,  9, 14)
          end

          stream = []
          for i in 0..15
            v = (x[i] + ctx[i]) & 0xffffffff
            enum.yield(v & 0xff)
            enum.yield(v >> 8 & 0xff)
            enum.yield(v >> 16 & 0xff)
            enum.yield(v >> 24 & 0xff)
          end
          ctx[12] = (ctx[12] + 1) & 0xffffffff
        end
      end
    end

    def self.chacha20_crypt(data, key, iv=nil, position=1)
      # Encrypt (or decrypt) with the ChaCha20 cipher.
      iv = "\0" * 12 if iv.nil?
      if key.length < 32
        key = (key * (32 / key.length + 1))[0..31]
      end

      enc = []
      stream = chacha20_xor_stream(key, iv, position)
      data.unpack("c*").each do |a|
        enc << (a.ord ^ stream.next)
      end
      enc.pack("c*").force_encoding('ASCII-8BIT')
    end

    def self.chacha_encrypt(key, iv, plaintext)
      return chacha20_crypt(plaintext, key, iv)
      cipher = OpenSSL::Cipher.new('chacha20')
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv

      cipher.update(plaintext) + cipher.final
    end

    def self.chacha_decrypt(key, iv, ciphertext)
      return chacha20_crypt(ciphertext, key, iv)
      decipher = OpenSSL::Cipher.new('chacha20')
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv

      decipher.update(ciphertext) + decipher.final
    end
=end
  end
end
