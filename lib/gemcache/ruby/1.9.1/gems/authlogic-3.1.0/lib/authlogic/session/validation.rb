module Authlogic
  module Session
    # Responsible for session validation
    module Validation
      # The errors in Authlogic work JUST LIKE ActiveRecord. In fact, it uses the exact same ActiveRecord errors class. Use it the same way:
      #
      #   class UserSession
      #     validate :check_if_awesome
      #
      #     private
      #       def check_if_awesome
      #         errors.add(:login, "must contain awesome") if login && !login.include?("awesome")
      #         errors.add(:base, "You must be awesome to log in") unless attempted_record.awesome?
      #       end
      #   end
      class Errors < (defined?(::ActiveModel) ? ::ActiveModel::Errors : ::ActiveRecord::Errors)
        unless defined?(::ActiveModel)
          def [](key)
            value = super
            value.is_a?(Array) ? value : [value].compact
          end
        end
      end
      
      # You should use this as a place holder for any records that you find during validation. The main reason for this is to
      # allow other modules to use it if needed. Take the failed_login_count feature, it needs this in order to increase
      # the failed login count.
      def attempted_record
        @attempted_record
      end
      
      # See attempted_record
      def attempted_record=(value)
        @attempted_record = value
      end
      
      # The errors in Authlogic work JUST LIKE ActiveRecord. In fact, it uses the exact same ActiveRecord errors class.
      # Use it the same way:
      #
      # === Example
      #
      #  class UserSession
      #    before_validation :check_if_awesome
      #
      #    private
      #      def check_if_awesome
      #        errors.add(:login, "must contain awesome") if login && !login.include?("awesome")
      #        errors.add(:base, "You must be awesome to log in") unless attempted_record.awesome?
      #      end
      #  end
      def errors
        @errors ||= Errors.new(self)
      end
      
      # Determines if the information you provided for authentication is valid or not. If there is
      # a problem with the information provided errors will be added to the errors object and this
      # method will return false.
      def valid?
        errors.clear
        self.attempted_record = nil
        
        before_validation
        new_session? ? before_validation_on_create : before_validation_on_update
        validate
        ensure_authentication_attempted
                
        if errors.size == 0
          new_session? ? after_validation_on_create : after_validation_on_update
          after_validation
        end
        
        save_record(attempted_record)
        errors.size == 0
      end
      
      private
        def ensure_authentication_attempted
          errors.add(:base, I18n.t('error_messages.no_authentication_details', :default => "You did not provide any details for authentication.")) if errors.empty? && attempted_record.nil?
        end
    end
  end
end
