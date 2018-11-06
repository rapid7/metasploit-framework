require 'net/ssh/errors'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the "none" SSH authentication method.
        class None < Abstract
          # Attempt to authenticate as "none"
          def authenticate(next_service, user="", password="")
            send_message(userauth_request(user, next_service, "none")) 
            message = session.next_message
            
            case message.type
            when USERAUTH_SUCCESS
              debug { "none succeeded" }
              return true
            when USERAUTH_FAILURE
              debug { "none failed" }
              
              raise Net::SSH::Authentication::DisallowedMethod unless
                message[:authentications].split(/,/).include? 'none'
              
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
