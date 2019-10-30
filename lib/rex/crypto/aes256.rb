# -*- coding: binary -*-

module Rex
  module Crypto

    # Returns an encrypted string using AES256-CBC.
    #
    # @param iv [String] Initialization vector.
    # @param key [String] Secret key.
    # @return [String] The encrypted string.
    def self.encrypt_aes256(iv, key, value)
      aes = OpenSSL::Cipher::AES256.new(:CBC)
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
      aes = OpenSSL::Cipher::AES256.new(:CBC)
      aes.decrypt
      aes.iv = iv
      aes.key = key
      aes.update(value) + aes.final
    end

  end
end