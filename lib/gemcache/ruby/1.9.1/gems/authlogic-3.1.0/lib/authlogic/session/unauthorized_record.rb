module Authlogic
  module Session
    # Allows you to create session with an object. Ex:
    #
    #   UserSession.create(my_user_object)
    #
    # Be careful with this, because Authlogic is assuming that you have already confirmed that the
    # user is who he says he is.
    #
    # For example, this is the method used to persist the session internally. Authlogic finds the user with
    # the persistence token. At this point we know the user is who he says he is, so Authlogic just creates a
    # session with the record. This is particularly useful for 3rd party authentication methods, such as
    # OpenID. Let that method verify the identity, once it's verified, pass the object and create a session.
    module UnauthorizedRecord
      def self.included(klass)
        klass.class_eval do
          attr_accessor :unauthorized_record
          validate :validate_by_unauthorized_record, :if => :authenticating_with_unauthorized_record?
        end
      end
      
      # Returning meaningful credentials
      def credentials
        if authenticating_with_unauthorized_record?
          details = {}
          details[:unauthorized_record] = "<protected>"
          details
        else
          super
        end
      end
      
      # Setting the unauthorized record if it exists in the credentials passed.
      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        self.unauthorized_record = values.first if values.first.class < ::ActiveRecord::Base
      end
      
      private
        def authenticating_with_unauthorized_record?
          !unauthorized_record.nil?
        end
        
        def validate_by_unauthorized_record
          self.attempted_record = unauthorized_record
        end
    end
  end
end