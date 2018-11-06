module Net
  module SSH
    module Authentication

      # Describes the constants used by the Net::SSH::Authentication components
      # of the Net::SSH library. Individual authentication method implemenations
      # may define yet more constants that are specific to their implementation.
      module Constants
        USERAUTH_REQUEST          = 50
        USERAUTH_FAILURE          = 51
        USERAUTH_SUCCESS          = 52
        USERAUTH_BANNER           = 53

        USERAUTH_PASSWD_CHANGEREQ = 60
        USERAUTH_PK_OK            = 60

        USERAUTH_METHOD_RANGE     = 60..79
      end
    end
  end
end
