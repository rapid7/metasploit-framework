module Authlogic
  module Session
    # Responsible for allowing you to persist your sessions.
    module Persistence
      def self.included(klass)
        klass.class_eval do
          extend ClassMethods
          include InstanceMethods
        end
      end
      
      module ClassMethods
        # This is how you persist a session. This finds the record for the current session using
        # a variety of methods. It basically tries to "log in" the user without the user having
        # to explicitly log in. Check out the other Authlogic::Session modules for more information.
        #
        # The best way to use this method is something like:
        #
        #   helper_method :current_user_session, :current_user
        #
        #   def current_user_session
        #     return @current_user_session if defined?(@current_user_session)
        #     @current_user_session = UserSession.find
        #   end
        #
        #   def current_user
        #     return @current_user if defined?(@current_user)
        #     @current_user = current_user_session && current_user_session.user
        #   end
        #
        # Also, this method accepts a single parameter as the id, to find session that you marked with an id:
        #
        #   UserSession.find(:secure)
        #
        # See the id method for more information on ids.
        def find(id = nil, priority_record = nil)
          session = new({:priority_record => priority_record}, id)
          session.priority_record = priority_record
          if session.persisting?
            session
          else
            nil
          end
        end
      end
      
      module InstanceMethods
        # Let's you know if the session is being persisted or not, meaning the user does not have to explicitly log in
        # in order to be logged in. If the session has no associated record, it will try to find a record and persis
        # the session. This is the method that the class level method find uses to ultimately persist the session.
        def persisting?
          return true if !record.nil?
          self.attempted_record = nil
          before_persisting
          persist
          ensure_authentication_attempted
          if errors.empty? && !attempted_record.nil?
            self.record = attempted_record
            after_persisting
            save_record
            self.new_session = false
            true
          else
            false
          end
        end
      end
    end
  end
end