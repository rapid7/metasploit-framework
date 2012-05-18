module Authlogic
  module Session
    # Handles all parts of authentication that deal with sessions. Such as persisting a session and saving / destroy a session.
    module Session
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
          persist :persist_by_session
          after_save :update_session
          after_destroy :update_session
          after_persisting :update_session, :unless => :single_access?
        end
      end
      
      # Configuration for the session feature.
      module Config
        # Works exactly like cookie_key, but for sessions. See cookie_key for more info.
        #
        # * <tt>Default:</tt> cookie_key
        # * <tt>Accepts:</tt> Symbol or String
        def session_key(value = nil)
          rw_config(:session_key, value, cookie_key)
        end
        alias_method :session_key=, :session_key
      end
      
      # Instance methods for the session feature.
      module InstanceMethods
        private
          # Tries to validate the session from information in the session
          def persist_by_session
            persistence_token, record_id = session_credentials
            if !persistence_token.nil?
              # Allow finding by persistence token, because when records are created the session is maintained in a before_save, when there is no id.
              # This is done for performance reasons and to save on queries.
              record = record_id.nil? ?
                search_for_record("find_by_persistence_token", persistence_token) :
                search_for_record("find_by_#{klass.primary_key}", record_id)
              self.unauthorized_record = record if record && record.persistence_token == persistence_token
              valid?
            else
              false
            end
          end
          
          def session_credentials
            [controller.session[session_key], controller.session["#{session_key}_#{klass.primary_key}"]].compact
          end
          
          def session_key
            build_key(self.class.session_key)
          end
          
          def update_session
            controller.session[session_key] = record && record.persistence_token
            controller.session["#{session_key}_#{klass.primary_key}"] = record && record.send(record.class.primary_key)
          end
      end
    end
  end
end