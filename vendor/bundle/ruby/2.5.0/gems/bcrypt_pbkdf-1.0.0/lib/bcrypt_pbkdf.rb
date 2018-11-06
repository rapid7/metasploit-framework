begin
  RUBY_VERSION =~ /(\d+.\d+)/
  require "#{$1}/bcrypt_pbkdf_ext"
rescue LoadError
  require "bcrypt_pbkdf_ext"
end

module BCryptPbkdf
  # generates a key from a password + salt returning a string with keylen bytes
  # that can be used as cryptographic key.
  #
  # Remember to get a good random salt of at least 16 bytes.  Using a higher
  # rounds count will increase the cost of an exhaustive search but will also
  # make derivation proportionally slower.
  #
  # Example:
  #   rounds = 10
  #   keylen = 64
  #   @key = BCryptPbkdf.key("my secret", "my salt", keylen, rounds)
  def self.key(pass,salt,keylen,rounds)
    BCryptPbkdf::Engine::__bc_crypt_pbkdf(pass,salt,keylen,rounds)
  end
end

