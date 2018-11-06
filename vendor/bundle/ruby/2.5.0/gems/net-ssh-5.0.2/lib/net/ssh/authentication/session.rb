require 'net/ssh/loggable'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/authentication/key_manager'
require 'net/ssh/authentication/methods/none'
require 'net/ssh/authentication/methods/publickey'
require 'net/ssh/authentication/methods/hostbased'
require 'net/ssh/authentication/methods/password'
require 'net/ssh/authentication/methods/keyboard_interactive'

module Net
  module SSH
    module Authentication

      # Raised if the current authentication method is not allowed
      class DisallowedMethod < Net::SSH::Exception
      end

      # Represents an authentication session. It manages the authentication of
      # a user over an established connection (the "transport" object, see
      # Net::SSH::Transport::Session).
      #
      # The use of an authentication session to manage user authentication is
      # internal to Net::SSH (specifically Net::SSH.start). Consumers of the
      # Net::SSH library will never need to access this class directly.
      class Session
        include Loggable
        include Constants
        include Transport::Constants

        # transport layer abstraction
        attr_reader :transport

        # the list of authentication methods to try
        attr_reader :auth_methods

        # the list of authentication methods that are allowed
        attr_reader :allowed_auth_methods

        # a hash of options, given at construction time
        attr_reader :options

        # Instantiates a new Authentication::Session object over the given
        # transport layer abstraction.
        def initialize(transport, options={})
          self.logger = transport.logger
          @transport = transport

          @auth_methods = options[:auth_methods] || Net::SSH::Config.default_auth_methods
          @options = options

          @allowed_auth_methods = @auth_methods
        end

        # Attempts to authenticate the given user, in preparation for the next
        # service request. Returns true if an authentication method succeeds in
        # authenticating the user, and false otherwise.
        def authenticate(next_service, username, password=nil)
          debug { "beginning authentication of `#{username}'" }

          transport.send_message(transport.service_request("ssh-userauth"))
          expect_message(SERVICE_ACCEPT)

          key_manager = KeyManager.new(logger, options)
          keys.each { |key| key_manager.add(key) } unless keys.empty?
          key_data.each { |key2| key_manager.add_key_data(key2) } unless key_data.empty?
          default_keys.each { |key| key_manager.add(key) } unless options.key?(:keys) || options.key?(:key_data)

          attempted = []

          @auth_methods.each do |name|
            begin
              next unless @allowed_auth_methods.include?(name)
              attempted << name

              debug { "trying #{name}" }
              begin
                auth_class = Methods.const_get(name.split(/\W+/).map { |p| p.capitalize }.join)
                method = auth_class.new(self, key_manager: key_manager, password_prompt: options[:password_prompt])
              rescue NameError
                debug {"Mechanism #{name} was requested, but isn't a known type.  Ignoring it."}
                next
              end

              return true if method.authenticate(next_service, username, password)
            rescue Net::SSH::Authentication::DisallowedMethod
            end
          end

          error { "all authorization methods failed (tried #{attempted.join(', ')})" }
          return false
        ensure
          key_manager.finish if key_manager
        end

        # Blocks until a packet is received. It silently handles USERAUTH_BANNER
        # packets, and will raise an error if any packet is received that is not
        # valid during user authentication.
        def next_message
          loop do
            packet = transport.next_message

            case packet.type
            when USERAUTH_BANNER
              info { packet[:message] }
            # TODO add a hook for people to retrieve the banner when it is sent

            when USERAUTH_FAILURE
              @allowed_auth_methods = packet[:authentications].split(/,/)
              debug { "allowed methods: #{packet[:authentications]}" }
              return packet

            when USERAUTH_METHOD_RANGE, SERVICE_ACCEPT
              return packet

            when USERAUTH_SUCCESS
              transport.hint :authenticated
              return packet

            else
              raise Net::SSH::Exception, "unexpected message #{packet.type} (#{packet})"
            end
          end
        end

        # Blocks until a packet is received, and returns it if it is of the given
        # type. If it is not, an exception is raised.
        def expect_message(type)
          message = next_message
          raise Net::SSH::Exception, "expected #{type}, got #{message.type} (#{message})" unless message.type == type
          message
        end

        private

        # Returns an array of paths to the key files usually defined
        # by system default.
        def default_keys
          if defined?(OpenSSL::PKey::EC)
            %w[~/.ssh/id_ed25519 ~/.ssh/id_rsa ~/.ssh/id_dsa ~/.ssh/id_ecdsa
               ~/.ssh2/id_ed25519 ~/.ssh2/id_rsa ~/.ssh2/id_dsa ~/.ssh2/id_ecdsa]
          else
            %w[~/.ssh/id_dsa ~/.ssh/id_rsa ~/.ssh2/id_dsa ~/.ssh2/id_rsa]
          end
        end

        # Returns an array of paths to the key files that should be used when
        # attempting any key-based authentication mechanism.
        def keys
          Array(options[:keys])
        end

        # Returns an array of the key data that should be used when
        # attempting any key-based authentication mechanism.
        def key_data
          Array(options[:key_data])
        end
      end
    end
  end
end
