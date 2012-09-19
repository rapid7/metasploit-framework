require 'test_helper'

module CryptoProviderTest
  class Sha1Test < ActiveSupport::TestCase
    def test_encrypt
      assert Authlogic::CryptoProviders::Sha1.encrypt("mypass")
    end
    
    def test_matches
      hash = Authlogic::CryptoProviders::Sha1.encrypt("mypass")
      assert Authlogic::CryptoProviders::Sha1.matches?(hash, "mypass")
    end
    
    def test_old_restful_authentication_passwords
      password = "test"
      salt = "7e3041ebc2fc05a40c60028e2c4901a81035d3cd"
      digest = "00742970dc9e6319f8019fd54864d3ea740f04b1"
      Authlogic::CryptoProviders::Sha1.stretches = 1
      assert Authlogic::CryptoProviders::Sha1.matches?(digest, nil, salt, password, nil)
      Authlogic::CryptoProviders::Sha1.stretches = 10
    end
  end
end