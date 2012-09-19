module Authlogic
  module Session
    # Allows you to separate sessions with an id, ultimately letting you create multiple sessions for the same user.
    module Id
      def self.included(klass)
        klass.class_eval do
          attr_writer :id
        end
      end
      
      # Setting the id if it is passed in the credentials.
      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        self.id = values.last if values.last.is_a?(Symbol)
      end
      
      # Allows you to set a unique identifier for your session, so that you can have more than 1 session at a time.
      # A good example when this might be needed is when you want to have a normal user session and a "secure" user session.
      # The secure user session would be created only when they want to modify their billing information, or other sensitive
      # information. Similar to me.com. This requires 2 user sessions. Just use an id for the "secure" session and you should be good.
      #
      # You can set the id during initialization (see initialize for more information), or as an attribute:
      #
      #   session.id = :my_id
      #
      # Just be sure and set your id before you save your session.
      #
      # Lastly, to retrieve your session with the id check out the find class method.
      def id
        @id
      end
      
      private
        # Used for things like cookie_key, session_key, etc.
        def build_key(last_part)
          [id, super].compact.join("_")
        end
    end
  end
end