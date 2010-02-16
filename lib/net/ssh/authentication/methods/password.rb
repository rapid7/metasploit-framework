require 'net/ssh/errors'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the "password" SSH authentication method.
        class Password < Abstract
          # Attempt to authenticate the given user for the given service. If
          # the password parameter is nil, this will never do anything except
          # return false.
          def authenticate(next_service, username, password=nil)
            return false unless password

            send_message(userauth_request(username, next_service, "password", false, password))
            message = session.next_message

            case message.type
              when USERAUTH_SUCCESS
                debug { "password succeeded" }
                return true
              when USERAUTH_FAILURE
                debug { "password failed" }
                return false
              when USERAUTH_PASSWD_CHANGEREQ
                debug { "password change request received, failing" }
                return false
              else
                raise Net::SSH::Exception, "unexpected reply to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
            end
          end
        end

      end
    end
  end
end
