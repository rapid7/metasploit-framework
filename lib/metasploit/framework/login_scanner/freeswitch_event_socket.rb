require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/tcp/client'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with FreeSWITCH EventSocket.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.

      class FreeswitchEventSocket
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        DEFAULT_PORT         = 8021
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'freeswitch' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = nil

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
            service_name: 'freeswitch'
          }

          disconnect if self.sock

          begin
            connect
            select([sock], nil, nil, 0.4)

            sock.get_once
            sock.put("auth #{credential.private}\n\n")

            /Reply-Text: (?<reply>.*)/ =~ sock.get_once
            result_options[:proof] = reply

            # Invalid password - ( -ERR invalid\n\n )
            # Valid password   - ( +OK accepted\n\n )

            if result_options[:proof]&.include?('-ERR invalid')
              result_options[:status] = Metasploit::Model::Login::Status::INCORRECT
            elsif result_options[:proof]&.include?('+OK accepted')
              result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
            end

          rescue Rex::ConnectionError, EOFError, Timeout::Error, Errno::EPIPE, Rex::StreamClosedError => e
            result_options.merge!(
              proof: e.message,
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            )
          end
          disconnect if self.sock
          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        private

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.connection_timeout  ||= 10
          self.port                ||= DEFAULT_PORT
          self.max_send_size       ||= 0
          self.send_delay          ||= 0
        end
      end
    end
  end
end
