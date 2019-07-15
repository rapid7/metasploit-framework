# -*- coding: binary -*-

module Rex
  module Crypto
    def self.chacha_encrypt(key, iv, plaintext)
      cipher = OpenSSL::Cipher.new('chacha20')
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv

      cipher.update(plaintext) + final 
    end

    def self.chacha_decrypt(key, iv, ciphertext)
      cipher = OpenSSL::Cipher.new('chacha20')
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv

      cipher.update(ciphertext) + final
    end

  end
end
