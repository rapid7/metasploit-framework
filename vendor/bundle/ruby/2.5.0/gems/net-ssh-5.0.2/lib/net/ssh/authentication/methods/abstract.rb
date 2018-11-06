require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/authentication/constants'

module Net
  module SSH
    module Authentication
      module Methods

        # The base class of all user authentication methods. It provides a few
        # bits of common functionality.
        class Abstract
          include Loggable
          include Constants

          # The authentication session object
          attr_reader :session

          # The key manager object. Not all authentication methods will require
          # this.
          attr_reader :key_manager

          # Instantiates a new authentication method.
          def initialize(session, options={})
            @session = session
            @key_manager = options[:key_manager]
            @options = options
            @prompt = options[:password_prompt]
            self.logger = session.logger
          end

          # Returns the session-id, as generated during the first key exchange of
          # an SSH connection.
          def session_id
            session.transport.algorithms.session_id
          end

          # Sends a message via the underlying transport layer abstraction. This
          # will block until the message is completely sent.
          def send_message(msg)
            session.transport.send_message(msg)
          end

          # Creates a new USERAUTH_REQUEST packet. The extra arguments on the end
          # must be either boolean values or strings, and are tacked onto the end
          # of the packet. The new packet is returned, ready for sending.
          def userauth_request(username, next_service, auth_method, *others)
            buffer = Net::SSH::Buffer.from(:byte, USERAUTH_REQUEST,
              :string, username, :string, next_service, :string, auth_method)

            others.each do |value|
              case value
              when true, false then buffer.write_bool(value)
              when String      then buffer.write_string(value)
              else raise ArgumentError, "don't know how to write #{value.inspect}"
              end
            end

            buffer
          end

          private

          attr_reader :prompt
        end
      end
    end
  end
end
