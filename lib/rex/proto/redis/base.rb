module Rex
  module Proto
    module Redis
      # Module containing the constants and functionality for any Redis version.
      # When a behavior changes, check whether a more recent version module exits
      # and include the constants from there, or use the functionality defined there.
      module Base
        module Constants
          AUTHENTICATION_REQUIRED   = /(?<auth_response>NOAUTH Authentication required)/i
          NO_PASSWORD_SET           = /(?<auth_response>ERR Client sent AUTH, but no password is set)/i
          WRONG_PASSWORD            = /(?<auth_response>ERR invalid password)/i
          WRONG_ARGUMENTS_FOR_AUTH  = /(?<auth_response>ERR wrong number of arguments for 'auth' command)/i
          OKAY                      = /\+OK/i
        end
      end
    end
  end
end
