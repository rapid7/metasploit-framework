module Rex::Crypto
  # Returns an encrypted string using AES256-CBC.
  #
  # @deprecated Access via Rex::Crypto::Aes256
  # @param iv [String] Initialization vector.
  # @param key [String] Secret key.
  # @return [String] The encrypted string.
  def self.encrypt_aes256(iv, key, value)
    Aes256.encrypt_aes256(iv, key, value)
  end

  # Returns a decrypted string using AES256-CBC.
  #
  # @deprecated Access via Rex::Crypto::Aes256
  # @param iv [String] Initialization vector.
  # @param key [String] Secret key.
  # @return [String] The decrypted string.
  def self.decrypt_aes256(iv, key, value)
    Aes256.decrypt_aes256(iv, key, value)
  end

  # Returns a decrypted or encrypted RC4 string.
  #
  # @deprecated Access via Rex::Crypto::Rc4
  # @param key [String] Secret key.
  # @param [String]
  def self.rc4(key, value)
    Rc4.rc4(key, value)
  end
end
