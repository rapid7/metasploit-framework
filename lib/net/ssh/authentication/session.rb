# -*- coding: binary -*-
require 'net/ssh/loggable'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/authentication/key_manager'
require 'net/ssh/authentication/methods/publickey'
require 'net/ssh/authentication/methods/hostbased'
require 'net/ssh/authentication/methods/password'
require 'net/ssh/authentication/methods/keyboard_interactive'

module Net; module SSH; module Authentication

  # Represents an authentication session. It manages the authentication of
  # a user over an established connection (the "transport" object, see
  # Net::SSH::Transport::Session).
  #
  # The use of an authentication session to manage user authentication is
  # internal to Net::SSH (specifically Net::SSH.start). Consumers of the
  # Net::SSH library will never need to access this class directly.
  class Session
    include Transport::Constants, Constants, Loggable

    # transport layer abstraction
    attr_reader :transport

    # the list of authentication methods to try
    attr_reader :auth_methods

    # the list of authentication methods that are allowed
    attr_reader :allowed_auth_methods

    # a hash of options, given at construction time
    attr_reader :options

    # when a successful auth is made, note the auth info if session.options[:record_auth_info]
    attr_accessor :auth_info
    
    # when a public key is accepted (even if not used), trigger a callback
    attr_accessor :accepted_key_callback
    
    # when we only want to test a key and not login
    attr_accessor :skip_private_keys

    # Instantiates a new Authentication::Session object over the given
    # transport layer abstraction.
    def initialize(transport, options={})
      self.logger = transport.logger
      @transport = transport

      @auth_methods = options[:auth_methods] || %w(publickey hostbased password keyboard-interactive)
      @options = options

      @allowed_auth_methods  = @auth_methods
      @skip_private_keys     = options[:skip_private_keys] || false
      @accepted_key_callback = options[:accepted_key_callback]     
      @auth_info = {}      
    end

    # Attempts to authenticate the given user, in preparation for the next
    # service request. Returns true if an authentication method succeeds in
    # authenticating the user, and false otherwise.
    def authenticate(next_service, username, password=nil)
      debug { "beginning authentication of `#{username}'" }

      transport.send_message(transport.service_request("ssh-userauth"))
      message = expect_message(SERVICE_ACCEPT)

      key_manager = KeyManager.new(logger, options)
      keys.each { |key| key_manager.add(key) } unless keys.empty?
      key_data.each { |key2| key_manager.add_key_data(key2) } unless key_data.empty?

      attempted = []

      @auth_methods.each do |name|
        next unless @allowed_auth_methods.include?(name)
        attempted << name

        debug { "trying #{name}" }
        method = Methods.const_get(name.split(/\W+/).map { |p| p.capitalize }.join).new(self, :key_manager => key_manager)

        return true if method.authenticate(next_service, username, password)
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
      unless message.type == type
        raise Net::SSH::Exception, "expected #{type}, got #{message.type} (#{message})"
      end
      message
    end

    private

      # Returns an array of paths to the key files that should be used when
      # attempting any key-based authentication mechanism.
      def keys
      Array(
        options[:keys] # ||
        # %w(~/.ssh/id_dsa ~/.ssh/id_rsa ~/.ssh2/id_dsa ~/.ssh2/id_rsa)
        )
      end

      # Returns an array of the key data that should be used when
      # attempting any key-based authentication mechanism.
      def key_data
        Array(options[:key_data])
      end
  end
end; end; end

