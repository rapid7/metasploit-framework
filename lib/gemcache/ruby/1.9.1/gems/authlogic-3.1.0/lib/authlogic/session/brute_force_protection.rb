module Authlogic
  module Session
    # A brute force attacks is executed by hammering a login with as many password combinations as possible, until one works. A brute force attacked is
    # generally combated with a slow hasing algorithm such as BCrypt. You can increase the cost, which makes the hash generation slower, and ultimately
    # increases the time it takes to execute a brute force attack. Just to put this into perspective, if a hacker was to gain access to your server
    # and execute a brute force attack locally, meaning there is no network lag, it would probably take decades to complete. Now throw in network lag
    # and it would take MUCH longer.
    #
    # But for those that are extra paranoid and can't get enough protection, why not stop them as soon as you realize something isn't right? That's
    # what this module is all about. By default the consecutive_failed_logins_limit configuration option is set to 50, if someone consecutively fails to login
    # after 50 attempts their account will be suspended. This is a very liberal number and at this point it should be obvious that something is not right.
    # If you wish to lower this number just set the configuration to a lower number:
    #
    #   class UserSession < Authlogic::Session::Base
    #     consecutive_failed_logins_limit 10
    #   end
    module BruteForceProtection
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
          validate :reset_failed_login_count, :if => :reset_failed_login_count?
          validate :validate_failed_logins, :if => :being_brute_force_protected?
        end
      end
      
      # Configuration for the brute force protection feature.
      module Config
        # To help protect from brute force attacks you can set a limit on the allowed number of consecutive failed logins. By default this is 50, this is a very liberal
        # number, and if someone fails to login after 50 tries it should be pretty obvious that it's a machine trying to login in and very likely a brute force attack.
        #
        # In order to enable this field your model MUST have a failed_login_count (integer) field.
        #
        # If you don't know what a brute force attack is, it's when a machine tries to login into a system using every combination of character possible. Thus resulting
        # in possibly millions of attempts to log into an account.
        #
        # * <tt>Default:</tt> 50
        # * <tt>Accepts:</tt> Integer, set to 0 to disable
        def consecutive_failed_logins_limit(value = nil)
          rw_config(:consecutive_failed_logins_limit, value, 50)
        end
        alias_method :consecutive_failed_logins_limit=, :consecutive_failed_logins_limit
        
        # Once the failed logins limit has been exceed, how long do you want to ban the user? This can be a temporary or permanent ban.
        #
        # * <tt>Default:</tt> 2.hours
        # * <tt>Accepts:</tt> Fixnum, set to 0 for permanent ban
        def failed_login_ban_for(value = nil)
          rw_config(:failed_login_ban_for, (!value.nil? && value) || value, 2.hours.to_i)
        end
        alias_method :failed_login_ban_for=, :failed_login_ban_for
      end
      
      # The methods available for an Authlogic::Session::Base object that make up the brute force protection feature.
      module InstanceMethods
        # Returns true when the consecutive_failed_logins_limit has been exceeded and is being temporarily banned.
        # Notice the word temporary, the user will not be permanently banned unless you choose to do so with configuration.
        # By default they will be banned for 2 hours. During that 2 hour period this method will return true.
        def being_brute_force_protected?
          exceeded_failed_logins_limit? && (failed_login_ban_for <= 0 ||
            (attempted_record.respond_to?(:updated_at) && attempted_record.updated_at >= failed_login_ban_for.seconds.ago))
        end
        
        private
          def exceeded_failed_logins_limit?
            !attempted_record.nil? && attempted_record.respond_to?(:failed_login_count) && consecutive_failed_logins_limit > 0 &&
              attempted_record.failed_login_count && attempted_record.failed_login_count >= consecutive_failed_logins_limit
          end
          
          def reset_failed_login_count?
            exceeded_failed_logins_limit? && !being_brute_force_protected?
          end
          
          def reset_failed_login_count
            attempted_record.failed_login_count = 0
          end
        
          def validate_failed_logins
            errors.clear # Clear all other error messages, as they are irrelevant at this point and can only provide additional information that is not needed
            errors.add(:base, I18n.t(
              'error_messages.consecutive_failed_logins_limit_exceeded', 
              :default => "Consecutive failed logins limit exceeded, account has been" + (failed_login_ban_for == 0 ? "" : " temporarily") + " disabled."
            ))
          end
          
          def consecutive_failed_logins_limit
            self.class.consecutive_failed_logins_limit
          end
          
          def failed_login_ban_for
            self.class.failed_login_ban_for
          end
      end
    end
  end
end