require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/tcp/client'
require 'rex/proto/redis'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with REDIS.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class Redis
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        # Required to be able to invoke the scan! method from the included Base module.
        # We do not use inheritance, so overwriting a method and relying on super does
        # not work in this case.
        alias parent_scan! scan!

        DEFAULT_PORT          = 6379
        LIKELY_PORTS          = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES  = [ 'redis' ]
        PRIVATE_TYPES         = [ :password ]
        REALM_KEY             = nil

        # Attempt to login with every {Credential credential} in
        # {#cred_details}, by calling {#attempt_login} once for each.
        #
        # If a successful login is found for a user, no more attempts
        # will be made for that user. If the scanner detects that no
        # authentication is required, no further attempts will be made
        # at all.
        #
        # @yieldparam result [Result] The {Result} object for each attempt
        # @yieldreturn [void]
        # @return [void]
        def scan!(&block)
          first_credential = to_enum(:each_credential).first
          result = attempt_login(first_credential)
          result.freeze

          if result.status == Metasploit::Model::Login::Status::NO_AUTH_REQUIRED
            yield result if block_given?
          else
            parent_scan!(&block)
          end
        end

        # This method can create redis command which can be read by redis server
        def redis_proto(command_parts)
          return if command_parts.blank?

          command = "*#{command_parts.length}\r\n"
          command_parts.each do |p|
            command << "$#{p.length}\r\n#{p}\r\n"
          end
          command
        end

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attempt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            host: host,
            port: port,
            protocol: 'tcp',
            service_name: 'redis'
          }

          disconnect if sock

          begin
            connect
            select([sock], nil, nil, 0.4)

            # Skip this call if we're dealing with an older redis version.
            response = authenticate(credential.public.to_s, credential.private.to_s) unless @older_redis

            # If we're dealing with an older redis version or the previous call failed,
            # try the backwards compatibility call instead.
            # We also set the @older_redis to true if we haven't as we might be entering this
            # block from the match response.
            if @older_redis || (response && response.match(::Rex::Proto::Redis::Base::Constants::WRONG_ARGUMENTS_FOR_AUTH))
              @older_redis ||= true
              response = authenticate_pre_v6(credential.private.to_s)
            end

            result_options[:proof] = response
            result_options[:status] = validate_login(result_options[:proof])
          rescue Rex::ConnectionError, EOFError, Timeout::Error, Errno::EPIPE => e
            result_options.merge!(
              proof: e,
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            )
          end

          disconnect if sock

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        private

        # Authenticates against Redis using the provided credentials arguments.
        # Takes either a password, or a username and password combination.
        #
        # @param [String] username The username to authenticate with, defaults to 'default'
        # @param [String] password The password to authenticate with.
        # @return [String] The response from Redis for the AUTH command.
        def authenticate(username, password)
          command = redis_proto(['AUTH', username.blank? ? 'default' : username, password])
          sock.put(command)
          sock.get_once
        end

        # Authenticates against Redis using the provided password.
        # This method is for older Redis instances of backwards compatibility.
        #
        # @param [String] password The password to authenticate with.
        # @return [String] The response from Redis for the AUTH command.
        def authenticate_pre_v6(password)
          command = redis_proto(['AUTH', password])
          sock.put(command)
          sock.get_once
        end

        # Validates the login data received from Redis and returns the correct Login status
        # based upon the contents Redis sent back:
        #
        # No password      - ( -ERR Client sent AUTH, but no password is set\r\n )
        # Invalid password - ( -ERR invalid password\r\n )
        # Valid password   - (+OK\r\n)
        def validate_login(data)
          return if data.nil?

          return Metasploit::Model::Login::Status::NO_AUTH_REQUIRED if no_password_set?(data)
          return Metasploit::Model::Login::Status::INCORRECT if invalid_password?(data)
          return Metasploit::Model::Login::Status::SUCCESSFUL if data.match(::Rex::Proto::Redis::Base::Constants::OKAY)

          nil
        end

        def no_password_set?(data)
          data.match(::Rex::Proto::Redis::Base::Constants::NO_PASSWORD_SET) ||
            data.match(::Rex::Proto::Redis::Version6::Constants::NO_PASSWORD_SET)
        end

        def invalid_password?(data)
          data.match(::Rex::Proto::Redis::Base::Constants::WRONG_PASSWORD) ||
            data.match(::Rex::Proto::Redis::Version6::Constants::WRONG_PASSWORD)
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.connection_timeout ||= 30
          self.port               ||= DEFAULT_PORT
          self.max_send_size      ||= 0
          self.send_delay         ||= 0
        end
      end
    end
  end
end
