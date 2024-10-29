module Rex
  module Proto
    module Redis
      # Module containing the required constants and functionality
      # specifically for Redis 6 and newer.
      module Version6
        module Constants
          AUTHENTICATION_REQUIRED = /(?<auth_response>NOAUTH Authentication required)/i
          NO_PASSWORD_SET         = /(?<auth_response>ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?)/i
          WRONG_PASSWORD          = /(?<auth_response>WRONGPASS invalid username-password pair or user is disabled)/i
        end
      end
    end
  end
end
