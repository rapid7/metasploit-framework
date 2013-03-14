module Authlogic
  module ActsAsAuthentic
    # This module is responsible for transitioning existing applications from the restful_authentication plugin.
    module RestfulAuthentication
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
        end
      end
      
      module Config
        # Switching an existing app to Authlogic from restful_authentication? No problem, just set this true and your users won't know
        # anything changed. From your database perspective nothing will change at all. Authlogic will continue to encrypt passwords
        # just like restful_authentication, so your app won't skip a beat. Although, might consider transitioning your users to a newer
        # and stronger algorithm. Checkout the transition_from_restful_authentication option.
        #
        # * <tt>Default:</tt> false
        # * <tt>Accepts:</tt> Boolean
        def act_like_restful_authentication(value = nil)
          r = rw_config(:act_like_restful_authentication, value, false)
          set_restful_authentication_config if value
          r
        end
        alias_method :act_like_restful_authentication=, :act_like_restful_authentication
        
        # This works just like act_like_restful_authentication except that it will start transitioning your users to the algorithm you
        # specify with the crypto provider option. The next time they log in it will resave their password with the new algorithm
        # and any new record will use the new algorithm as well. Make sure to update your users table if you are using the default
        # migration since it will set crypted_password and salt columns to a maximum width of 40 characters which is not enough. 
        def transition_from_restful_authentication(value = nil)
          r = rw_config(:transition_from_restful_authentication, value, false)
          set_restful_authentication_config if value
          r
        end
        alias_method :transition_from_restful_authentication=, :transition_from_restful_authentication
        
        private
          def set_restful_authentication_config
            crypto_provider_key = act_like_restful_authentication ? :crypto_provider : :transition_from_crypto_providers
            self.send("#{crypto_provider_key}=", CryptoProviders::Sha1)
            if !defined?(::REST_AUTH_SITE_KEY) || ::REST_AUTH_SITE_KEY.nil?
              class_eval("::REST_AUTH_SITE_KEY = ''") if !defined?(::REST_AUTH_SITE_KEY)
              CryptoProviders::Sha1.stretches = 1
            end
          end
      end
      
      module InstanceMethods
        private
          def act_like_restful_authentication?
            self.class.act_like_restful_authentication == true
          end
          
          def transition_from_restful_authentication?
            self.class.transition_from_restful_authentication == true
          end
      end
    end
  end
end