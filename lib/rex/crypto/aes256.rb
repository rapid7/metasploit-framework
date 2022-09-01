# -*- coding: binary -*-

module Rex
  module Crypto
    module Aes256
      # Returns an encrypted string using AES256-CBC.
      #
      # @param iv [String] Initialization vector.
      # @param key [String] Secret key.
      # @return [String] The encrypted string.
      def self.encrypt_aes256(iv, key, value)
        aes = OpenSSL::Cipher.new('aes-256-cbc')
        aes.encrypt
        aes.iv = iv
        aes.key = key
        aes.update(value) + aes.final
      end

      # Returns a decrypted string using AES256-CBC.
      #
      # @param iv [String] Initialization vector.
      # @param key [String] Secret key.
      # @return [String] The decrypted string.
      def self.decrypt_aes256(iv, key, value)
        aes = OpenSSL::Cipher.new('aes-256-cbc')
        aes.decrypt
        aes.iv = iv
        aes.key = key
        aes.update(value) + aes.final
      end

    end
  end
end
