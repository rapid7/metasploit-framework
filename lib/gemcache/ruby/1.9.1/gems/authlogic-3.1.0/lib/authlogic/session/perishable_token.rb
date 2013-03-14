module Authlogic
  module Session
    # Maintains the perishable token, which is helpful for confirming records or authorizing records to reset their password. All that this
    # module does is reset it after a session have been saved, just keep it changing. The more it changes, the tighter the security.
    #
    # See Authlogic::ActsAsAuthentic::PerishableToken for more information.
    module PerishableToken
      def self.included(klass)
        klass.after_save :reset_perishable_token!
      end
      
      private
        def reset_perishable_token!
          record.reset_perishable_token if record.respond_to?(:reset_perishable_token) && !record.disable_perishable_token_maintenance?
        end
    end
  end
end