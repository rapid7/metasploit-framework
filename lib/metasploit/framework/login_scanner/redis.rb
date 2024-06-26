require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/tcp/client'

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

        DEFAULT_PORT          = 6379
        LIKELY_PORTS          = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES  = [ 'redis' ]
        PRIVATE_TYPES         = [ :password ]
        REALM_KEY             = nil
        OLD_PASSWORD_NOT_SET  = /but no password is set/i
        PASSWORD_NOT_SET      = /without any password configured/i
        WRONG_PASSWORD_SET    = /^-WRONGPASS/i
        INVALID_PASSWORD_SET  = /^-ERR invalid password/i
        OK                    = /^\+OK/

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

          disconnect if self.sock

          begin
            connect
            select([sock], nil, nil, 0.4)

            command = redis_proto(['AUTH', credential.private.to_s])

            sock.put(command)

            result_options[:proof] = sock.get_once
            result_options[:status] = validate_login(result_options[:proof])
          rescue Rex::ConnectionError, EOFError, Timeout::Error, Errno::EPIPE => e
            result_options.merge!(
              proof: e,
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            )
          end

          disconnect if self.sock

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        private

        # Validates the login data received from Redis and returns the correct Login status
        # based upon the contents Redis sent back:
        #
        # No password      - ( -ERR Client sent AUTH, but no password is set\r\n )
        # Invalid password - ( -ERR invalid password\r\n )
        # Valid password   - (+OK\r\n)
        def validate_login(data)
          return if data.nil?

          return Metasploit::Model::Login::Status::NO_AUTH_REQUIRED if data =~ OLD_PASSWORD_NOT_SET
          return Metasploit::Model::Login::Status::NO_AUTH_REQUIRED if data =~ PASSWORD_NOT_SET
          return Metasploit::Model::Login::Status::INCORRECT if (data =~ INVALID_PASSWORD_SET) == 0
          return Metasploit::Model::Login::Status::INCORRECT if (data =~ WRONG_PASSWORD_SET) == 0
          return Metasploit::Model::Login::Status::SUCCESSFUL if (data =~ OK) == 0

          nil
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
