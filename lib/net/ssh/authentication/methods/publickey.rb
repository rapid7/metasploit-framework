# -*- coding: binary -*-
require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the "publickey" SSH authentication method.
        class Publickey < Abstract
          # Attempts to perform public-key authentication for the given
          # username, trying each identity known to the key manager. If any of
          # them succeed, returns +true+, otherwise returns +false+. This
          # requires the presence of a key manager.
          def authenticate(next_service, username, password=nil)
            return false unless key_manager

            key_manager.each_identity do |identity|
              return true if authenticate_with(identity, next_service, username)
            end

            return false
          end

          private

            # Builds a packet that contains the request formatted for sending
            # a public-key request to the server.
            def build_request(pub_key, username, next_service, has_sig)
              blob = Net::SSH::Buffer.new
              blob.write_key pub_key

              userauth_request(username, next_service, "publickey", has_sig,
                pub_key.ssh_type, blob.to_s)
            end

            # Builds and sends a request formatted for a public-key
            # authentication request.
            def send_request(pub_key, username, next_service, signature=nil)
              msg = build_request(pub_key, username, next_service, !signature.nil?)
              msg.write_string(signature) if signature
              send_message(msg)
            end

            # Attempts to perform public-key authentication for the given
            # username, with the given identity (public key). Returns +true+ if
            # successful, or +false+ otherwise.
            def authenticate_with(identity, next_service, username)
              debug { "trying publickey (#{identity.fingerprint})" }
              send_request(identity, username, next_service)

              message = session.next_message

              case message.type
                when USERAUTH_PK_OK
                  debug { "publickey will be accepted (#{identity.fingerprint})" }

                  # The key is accepted by the server, trigger a callback if set
                  if session.accepted_key_callback
                    session.accepted_key_callback.call({ :user => username, :fingerprint => identity.fingerprint, :key => identity.dup })
                  end 

                  if session.skip_private_keys
            if session.options[:record_auth_info]
            session.auth_info[:method] = "publickey"
            session.auth_info[:user] = username
            session.auth_info[:pubkey_data] = identity.inspect
            session.auth_info[:pubkey_id] = identity.fingerprint
            end        
                    return true
                  end
                  
                  buffer = build_request(identity, username, next_service, true)
                  sig_data = Net::SSH::Buffer.new
                  sig_data.write_string(session_id)
                  sig_data.append(buffer.to_s)

                  sig_blob = key_manager.sign(identity, sig_data)

                  send_request(identity, username, next_service, sig_blob.to_s)
                  message = session.next_message

                  case message.type
                    when USERAUTH_SUCCESS
                      debug { "publickey succeeded (#{identity.fingerprint})" }
            if session.options[:record_auth_info]
            session.auth_info[:method] = "publickey"
            session.auth_info[:user] = username
            session.auth_info[:pubkey_data] = identity.inspect
            session.auth_info[:pubkey_id] = identity.fingerprint
            end
              return true
                    when USERAUTH_FAILURE
                      debug { "publickey failed (#{identity.fingerprint})" }
                      return false
                    else
                      raise Net::SSH::Exception,
                        "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
                  end

                when USERAUTH_FAILURE
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
