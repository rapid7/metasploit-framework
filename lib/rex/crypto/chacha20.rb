# -*- coding: binary -*-

module Rex
  module Crypto
    def self.chacha_encrypt(key, iv, plaintext)
      cipher = OpenSSL::Cipher.new('chacha20')
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv

      cipher.update(plaintext) + cipher.final 
    end

    def self.chacha_decrypt(key, iv, ciphertext)
      decipher = OpenSSL::Cipher.new('chacha20')
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv

      decipher.update(ciphertext) + decipher.final
    end
  end
end
