module Authlogic
  module Session
    # Authlogic tries to check the state of the record before creating the session. If your record responds to the following methods and any of them return false, validation will fail:
    #
    #   Method name           Description
    #   active?               Is the record marked as active?
    #   approved?             Has the record been approved?
    #   confirmed?            Has the record been conirmed?
    #
    # Authlogic does nothing to define these methods for you, its up to you to define what they mean. If your object responds to these methods Authlogic will use them, otherwise they are ignored.
    #
    # What's neat about this is that these are checked upon any type of login. When logging in explicitly, by cookie, session, or basic http auth.
    # So if you mark a user inactive in the middle of their session they wont be logged back in next time they refresh the page. Giving you complete control.
    #
    # Need Authlogic to check your own "state"? No problem, check out the hooks section below. Add in a before_validation to do your own checking. The sky is the limit.
    module MagicStates
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
          validate :validate_magic_states, :unless => :disable_magic_states?
        end
      end
      
      # Configuration for the magic states feature.
      module Config
        # Set this to true if you want to disable the checking of active?, approved?, and confirmed? on your record. This is more or less of a
        # convenience feature, since 99% of the time if those methods exist and return false you will not want the user logging in. You could
        # easily accomplish this same thing with a before_validation method or other callbacks.
        #
        # * <tt>Default:</tt> false
        # * <tt>Accepts:</tt> Boolean
        def disable_magic_states(value = nil)
          rw_config(:disable_magic_states, value, false)
        end
        alias_method :disable_magic_states=, :disable_magic_states
      end
      
      # The methods available for an Authlogic::Session::Base object that make up the magic states feature.
      module InstanceMethods
        private
          def disable_magic_states?
            self.class.disable_magic_states == true
          end
        
          def validate_magic_states
            return true if attempted_record.nil?
            [:active, :approved, :confirmed].each do |required_status|
              if attempted_record.respond_to?("#{required_status}?") && !attempted_record.send("#{required_status}?")
                errors.add(:base, I18n.t("error_messages.not_#{required_status}", :default => "Your account is not #{required_status}"))
                return false
              end
            end
            true
          end
      end
    end
  end
end