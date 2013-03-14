require 'test_helper'

module CryptoProviderTest
  class Sha256Test < ActiveSupport::TestCase
    def test_encrypt
      assert Authlogic::CryptoProviders::Sha256.encrypt("mypass")
    end
    
    def test_matches
      hash = Authlogic::CryptoProviders::Sha256.encrypt("mypass")
      assert Authlogic::CryptoProviders::Sha256.matches?(hash, "mypass")
    end
  end
end
