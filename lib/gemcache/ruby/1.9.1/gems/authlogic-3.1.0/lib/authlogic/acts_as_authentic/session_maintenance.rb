module Authlogic
  module ActsAsAuthentic
    # This is one of my favorite features that I think is pretty cool. It's things like this that make a library great
    # and let you know you are on the right track.
    #
    # Just to clear up any confusion, Authlogic stores both the record id and the persistence token in the session.
    # Why? So stale sessions can not be persisted. It stores the id so it can quickly find the record, and the
    # persistence token to ensure no sessions are stale. So if the persistence token changes, the user must log
    # back in.
    #
    # Well, the persistence token changes with the password. What happens if the user changes his own password?
    # He shouldn't have to log back in, he's the one that made the change.
    #
    # That being said, wouldn't it be nice if their session and cookie information was automatically updated?
    # Instead of cluttering up your controller with redundant session code. The same thing goes for new
    # registrations.
    #
    # That's what this module is all about. This will automatically maintain the cookie and session values as
    # records are saved.
    module SessionMaintenance
      def self.included(klass)
        klass.class_eval do
          extend Config
          add_acts_as_authentic_module(Methods)
        end
      end
      
      module Config
        # This is more of a convenience method. In order to turn off automatic maintenance of sessions just
        # set this to false, or you can also set the session_ids method to a blank array. Both accomplish
        # the same thing. This method is a little clearer in it's intentions though.
        #
        # * <tt>Default:</tt> true
        # * <tt>Accepts:</tt> Boolean
        def maintain_sessions(value = nil)
          rw_config(:maintain_sessions, value, true)
        end
        alias_method :maintain_sessions=, :maintain_sessions
        
        # As you may know, authlogic sessions can be separate by id (See Authlogic::Session::Base#id). You can
        # specify here what session ids you want auto maintained. By default it is the main session, which has
        # an id of nil.
        #
        # * <tt>Default:</tt> [nil]
        # * <tt>Accepts:</tt> Array
        def session_ids(value = nil)
          rw_config(:session_ids, value, [nil])
        end
        alias_method :session_ids=, :session_ids
        
        # The name of the associated session class. This is inferred by the name of the model.
        #
        # * <tt>Default:</tt> "#{klass.name}Session".constantize
        # * <tt>Accepts:</tt> Class
        def session_class(value = nil)
          const = "#{base_class.name}Session".constantize rescue nil
          rw_config(:session_class, value, const)
        end
        alias_method :session_class=, :session_class
      end
      
      module Methods
        def self.included(klass)
          klass.class_eval do
            before_save :get_session_information, :if => :update_sessions?
            before_save :maintain_sessions, :if => :update_sessions?
          end
        end
        
        # Save the record and skip session maintenance all together.
        def save_without_session_maintenance(*args)
          self.skip_session_maintenance = true
          result = save(*args)
          self.skip_session_maintenance = false
          result
        end
        
        private
          def skip_session_maintenance=(value)
            @skip_session_maintenance = value
          end
          
          def skip_session_maintenance
            @skip_session_maintenance ||= false
          end
          
          def update_sessions?
            !skip_session_maintenance && session_class && session_class.activated? && self.class.maintain_sessions == true && !session_ids.blank? && persistence_token_changed?
          end
          
          def get_session_information
            # Need to determine if we are completely logged out, or logged in as another user
            @_sessions = []
            
            session_ids.each do |session_id|
              session = session_class.find(session_id, self)
              @_sessions << session if session && session.record
            end
          end
          
          def maintain_sessions
            if @_sessions.empty?
              create_session
            else
              update_sessions
            end
          end
          
          def create_session
            # We only want to automatically login into the first session, since this is the main session. The other sessions are sessions
            # that need to be created after logging into the main session.
            session_id = session_ids.first
            session_class.create(*[self, self, session_id].compact)

            return true
          end
          
          def update_sessions
            # We found sessions above, let's update them with the new info
            @_sessions.each do |stale_session|
              next if stale_session.record != self
              stale_session.unauthorized_record = self
              stale_session.save
            end

            return true
          end
          
          def session_ids
            self.class.session_ids
          end
          
          def session_class
            self.class.session_class
          end
      end
    end
  end
end