module Authlogic
  module Session # :nodoc:
    # This is the base class Authlogic, where all modules are included. For information on functiionality see the various
    # sub modules.
    class Base
      include Foundation
      include Callbacks
      
      # Included first so that the session resets itself to nil
      include Timeout
      
      # Included in a specific order so they are tried in this order when persisting
      include Params
      include Cookies
      include Session
      include HttpAuth
      
      # Included in a specific order so magic states gets ran after a record is found
      include Password
      include UnauthorizedRecord
      include MagicStates
      
      include Activation
      include ActiveRecordTrickery
      include BruteForceProtection
      include Existence
      include Klass
      include MagicColumns
      include PerishableToken
      include Persistence
      include Scopes
      include Id
      include Validation
      include PriorityRecord
    end
  end
end