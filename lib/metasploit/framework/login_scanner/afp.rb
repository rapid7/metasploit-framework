require 'metasploit/framework/tcp/client'
require 'metasploit/framework/afp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Apple Filing
      # Protocol.
      class AFP
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client
        include Metasploit::Framework::AFP::Client

        DEFAULT_PORT         = 548
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ "afp" ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = nil

        # @!attribute login_timeout
        #   @return [Integer] Number of seconds to wait before giving up
        attr_accessor :login_timeout

        def attempt_login(credential)
          begin
            connect
          rescue Rex::ConnectionError, EOFError, Timeout::Error
            status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          else
            begin
              success = login(credential.public, credential.private)
            rescue RuntimeError => e
              return {:status => Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, :proof => e.message}
            end

            status = (success == true) ? Metasploit::Model::Login::Status::SUCCESSFUL : Metasploit::Model::Login::Status::INCORRECT
          end

          result = Result.new(credential: credential, status: status)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = 'afp'
          result
        end

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
