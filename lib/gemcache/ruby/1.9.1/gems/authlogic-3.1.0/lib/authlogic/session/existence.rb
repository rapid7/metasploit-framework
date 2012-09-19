module Authlogic
  module Session
    # Provides methods to create and destroy objects. Basically controls their "existence".
    module Existence
      class SessionInvalidError < ::StandardError # :nodoc:
        def initialize(session)
          super("Your session is invalid and has the following errors: #{session.errors.full_messages.to_sentence}")
        end
      end
      
      def self.included(klass)
        klass.class_eval do
          extend ClassMethods
          include InstanceMethods
          attr_accessor :new_session, :record
        end
      end
      
      module ClassMethods
        # A convenince method. The same as:
        #
        #   session = UserSession.new(*args)
        #   session.save
        #
        # Instead you can do:
        #
        #   UserSession.create(*args)
        def create(*args, &block)
          session = new(*args)
          session.save(&block)
          session
        end
        
        # Same as create but calls create!, which raises an exception when validation fails.
        def create!(*args)
          session = new(*args)
          session.save!
          session
        end
      end
      
      module InstanceMethods
        # Clears all errors and the associated record, you should call this terminate a session, thus requring
        # the user to authenticate again if it is needed.
        def destroy
          before_destroy
          save_record
          errors.clear
          @record = nil
          after_destroy
          true
        end
        
        # Returns true if the session is new, meaning no action has been taken on it and a successful save
        # has not taken place.
        def new_session?
          new_session != false
        end
        
        # After you have specified all of the details for your session you can try to save it. This will
        # run validation checks and find the associated record, if all validation passes. If validation
        # does not pass, the save will fail and the erorrs will be stored in the errors object.
        def save(&block)
          result = nil
          if valid?
            self.record = attempted_record

            before_save
            new_session? ? before_create : before_update
            new_session? ? after_create : after_update
            after_save

            save_record
            self.new_session = false
            result = true
          else
            result = false
          end

          yield result if block_given?
          result
        end

        # Same as save but raises an exception of validation errors when validation fails
        def save!
          result = save
          raise SessionInvalidError.new(self) unless result
          result
        end
      end
    end
  end
end