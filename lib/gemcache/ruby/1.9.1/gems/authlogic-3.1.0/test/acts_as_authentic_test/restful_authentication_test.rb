require 'test_helper'

module ActsAsAuthenticTest
  class RestfulAuthenticationTest < ActiveSupport::TestCase
    def test_act_like_restful_authentication_config
      assert !User.act_like_restful_authentication
      assert !Employee.act_like_restful_authentication
  
      User.act_like_restful_authentication = true
      assert User.act_like_restful_authentication
      assert_equal Authlogic::CryptoProviders::Sha1, User.crypto_provider
      assert defined?(::REST_AUTH_SITE_KEY)
      assert_equal '', ::REST_AUTH_SITE_KEY
      assert_equal 1, Authlogic::CryptoProviders::Sha1.stretches

      User.act_like_restful_authentication false
      assert !User.act_like_restful_authentication
  
      User.crypto_provider = Authlogic::CryptoProviders::Sha512
      User.transition_from_crypto_providers = []
    end

    def test_transition_from_restful_authentication_config
      assert !User.transition_from_restful_authentication
      assert !Employee.transition_from_restful_authentication
      
      User.transition_from_restful_authentication = true
      assert User.transition_from_restful_authentication
      assert defined?(::REST_AUTH_SITE_KEY)
      assert_equal '', ::REST_AUTH_SITE_KEY
      assert_equal 1, Authlogic::CryptoProviders::Sha1.stretches
  
      User.transition_from_restful_authentication false
      assert !User.transition_from_restful_authentication
  
      User.crypto_provider = Authlogic::CryptoProviders::Sha512
      User.transition_from_crypto_providers = []
    end
  end
end