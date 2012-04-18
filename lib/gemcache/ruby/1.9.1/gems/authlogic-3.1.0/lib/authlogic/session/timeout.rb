module Authlogic
  module Session
    # Think about financial websites, if you are inactive for a certain period of time you will be asked to
    # log back in on your next request. You can do this with Authlogic easily, there are 2 parts to this:
    #
    # 1. Define the timeout threshold:
    #
    #   acts_as_authentic do |c|
    #     c.logged_in_timeout = 10.minutes # default is 10.minutes
    #   end
    #
    # 2. Enable logging out on timeouts
    #
    #   class UserSession < Authlogic::Session::Base
    #     logout_on_timeout true # default if false
    #   end
    #
    # This will require a user to log back in if they are inactive for more than 10 minutes. In order for
    # this feature to be used you must have a last_request_at datetime column in your table for whatever model
    # you are authenticating with.
    module Timeout
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
          before_persisting :reset_stale_state
          after_persisting :enforce_timeout
          attr_accessor :stale_record
        end
      end
      
      # Configuration for the timeout feature.
      module Config
        # With acts_as_authentic you get a :logged_in_timeout configuration option. If this is set, after this amount of time has passed the user
        # will be marked as logged out. Obviously, since web based apps are on a per request basis, we have to define a time limit threshold that
        # determines when we consider a user to be "logged out". Meaning, if they login and then leave the website, when do mark them as logged out?
        # I recommend just using this as a fun feature on your website or reports, giving you a ballpark number of users logged in and active. This is
        # not meant to be a dead accurate representation of a users logged in state, since there is really no real way to do this with web based apps.
        # Think about a user that logs in and doesn't log out. There is no action that tells you that the user isn't technically still logged in and
        # active.
        #
        # That being said, you can use that feature to require a new login if their session timesout. Similar to how financial sites work. Just set this option to
        # true and if your record returns true for stale? then they will be required to log back in.
        #
        # Lastly, UserSession.find will still return a object is the session is stale, but you will not get a record. This allows you to determine if the
        # user needs to log back in because their session went stale, or because they just aren't logged in. Just call current_user_session.stale? as your flag.
        #
        # * <tt>Default:</tt> false
        # * <tt>Accepts:</tt> Boolean
        def logout_on_timeout(value = nil)
          rw_config(:logout_on_timeout, value, false)
        end
        alias_method :logout_on_timeout=, :logout_on_timeout
      end
      
      # Instance methods for the timeout feature.
      module InstanceMethods
        # Tells you if the record is stale or not. Meaning the record has timed out. This will only return true if you set logout_on_timeout to true in your configuration.
        # Basically how a bank website works. If you aren't active over a certain period of time your session becomes stale and requires you to log back in.
        def stale?
          !stale_record.nil? || (logout_on_timeout? && record && record.logged_out?)
        end
    
        private
          def reset_stale_state
            self.stale_record = nil
          end
          
          def enforce_timeout
            if stale?
              self.stale_record = record
              self.record = nil
            end
          end
          
          def logout_on_timeout?
            self.class.logout_on_timeout == true
          end
      end
    end
  end
end