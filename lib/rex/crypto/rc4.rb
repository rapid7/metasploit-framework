# -*- coding: binary -*-

require 'rc4'

module Rex
  module Crypto

    # Returns a decrypted or encrypted RC4 string.
    #
    # @param key [String] Secret key.
    # @param [String]
    def self.rc4(key, value)
      rc4 = RC4.new(key)

      # This can also be used to decrypt
      rc4.encrypt(value)
    end

  end
end