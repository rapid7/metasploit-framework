require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the host-based SSH authentication method.
        class Hostbased < Abstract
          include Constants

          # Attempts to perform host-based authorization of the user by trying
          # all known keys.
          def authenticate(next_service, username, password=nil)
            return false unless key_manager

            key_manager.each_identity do |identity|
              return true if authenticate_with(identity, next_service,
                username, key_manager)
            end

            return false
          end

          private

          # Returns the hostname as reported by the underlying socket.
          def hostname
            session.transport.socket.client_name
          end

          # Attempts to perform host-based authentication of the user, using
          # the given host identity (key).
          def authenticate_with(identity, next_service, username, key_manager)
            debug { "trying hostbased (#{identity.fingerprint})" }
            client_username = ENV['USER'] || username

            req = build_request(identity, next_service, username, "#{hostname}.", client_username)
            sig_data = Buffer.from(:string, session_id, :raw, req)

            sig = key_manager.sign(identity, sig_data.to_s)

            message = Buffer.from(:raw, req, :string, sig)

            send_message(message)
            message = session.next_message

            case message.type
            when USERAUTH_SUCCESS
              info { "hostbased succeeded (#{identity.fingerprint})" }
              return true
            when USERAUTH_FAILURE
              info { "hostbased failed (#{identity.fingerprint})" }

              raise Net::SSH::Authentication::DisallowedMethod unless
                message[:authentications].split(/,/).include? 'hostbased'

              return false
            else
              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
            end
          end

          # Build the "core" hostbased request string.
          def build_request(identity, next_service, username, hostname, client_username)
            userauth_request(username, next_service, "hostbased", identity.ssh_type,
              Buffer.from(:key, identity).to_s, hostname, client_username).to_s
          end
        end

      end
    end
  end
end
