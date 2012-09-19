module Authlogic
  module ActsAsAuthentic
    # This module is responsible for maintaining the single_access token. For more information the single access token and how to use it,
    # see the Authlogic::Session::Params module.
    module SingleAccessToken
      def self.included(klass)
        klass.class_eval do
          extend Config
          add_acts_as_authentic_module(Methods)
        end
      end
      
      # All configuration for the single_access token aspect of acts_as_authentic.
      module Config
        # The single access token is used for authentication via URLs, such as a private feed. That being said,
        # if the user changes their password, that token probably shouldn't change. If it did, the user would have
        # to update all of their URLs. So be default this is option is disabled, if you need it, feel free to turn
        # it on.
        #
        # * <tt>Default:</tt> false
        # * <tt>Accepts:</tt> Boolean
        def change_single_access_token_with_password(value = nil)
          rw_config(:change_single_access_token_with_password, value, false)
        end
        alias_method :change_single_access_token_with_password=, :change_single_access_token_with_password
      end
      
      # All method, for the single_access token aspect of acts_as_authentic.
      module Methods
        def self.included(klass)
          return if !klass.column_names.include?("single_access_token")
          
          klass.class_eval do
            include InstanceMethods
            validates_uniqueness_of :single_access_token, :if => :single_access_token_changed?
            before_validation :reset_single_access_token, :if => :reset_single_access_token?
            after_password_set(:reset_single_access_token, :if => :change_single_access_token_with_password?) if respond_to?(:after_password_set)
          end
        end
        
        module InstanceMethods
          # Resets the single_access_token to a random friendly token.
          def reset_single_access_token
            self.single_access_token = Authlogic::Random.friendly_token
          end
        
          # same as reset_single_access_token, but then saves the record.
          def reset_single_access_token!
            reset_single_access_token
            save_without_session_maintenance
          end
      
          protected
            def reset_single_access_token?
              single_access_token.blank?
            end
          
            def change_single_access_token_with_password?
              self.class.change_single_access_token_with_password == true
            end
        end
      end
    end
  end
end