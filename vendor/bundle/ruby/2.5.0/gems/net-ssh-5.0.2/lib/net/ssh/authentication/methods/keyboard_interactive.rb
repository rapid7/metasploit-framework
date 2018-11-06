require 'net/ssh/prompt'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the "keyboard-interactive" SSH authentication method.
        class KeyboardInteractive < Abstract
          USERAUTH_INFO_REQUEST  = 60
          USERAUTH_INFO_RESPONSE = 61

          # Attempt to authenticate the given user for the given service.
          def authenticate(next_service, username, password=nil)
            debug { "trying keyboard-interactive" }
            send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))

            prompter = nil
            loop do
              message = session.next_message

              case message.type
              when USERAUTH_SUCCESS
                debug { "keyboard-interactive succeeded" }
                prompter.success if prompter
                return true
              when USERAUTH_FAILURE
                debug { "keyboard-interactive failed" }

                raise Net::SSH::Authentication::DisallowedMethod unless
                  message[:authentications].split(/,/).include? 'keyboard-interactive'

                return false unless interactive?
                password = nil
                debug { "retrying keyboard-interactive" }
                send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))
              when USERAUTH_INFO_REQUEST
                name = message.read_string
                instruction = message.read_string
                debug { "keyboard-interactive info request" }

                prompter = prompt.start(type: 'keyboard-interactive', name: name, instruction: instruction) if password.nil? && interactive? && prompter.nil?

                _ = message.read_string # lang_tag
                responses = []

                message.read_long.times do
                  text = message.read_string
                  echo = message.read_bool
                  password_to_send = password || (prompter && prompter.ask(text, echo))
                  responses << password_to_send
                end

                # if the password failed the first time around, don't try
                # and use it on subsequent requests.
                password = nil

                msg = Buffer.from(:byte, USERAUTH_INFO_RESPONSE, :long, responses.length, :string, responses)
                send_message(msg)
              else
                raise Net::SSH::Exception, "unexpected reply in keyboard interactive: #{message.type} (#{message.inspect})"
              end
            end
          end

          def interactive?
            options = session.transport.options || {}
            !options[:non_interactive]
          end
        end
      end
    end
  end
end
