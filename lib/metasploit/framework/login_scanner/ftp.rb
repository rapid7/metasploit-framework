require 'metasploit/framework/ftp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with FTP.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class FTP
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Ftp::Client

        DEFAULT_PORT         = 21
        LIKELY_PORTS         = [ DEFAULT_PORT, 2121 ]
        LIKELY_SERVICE_NAMES = [ 'ftp' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY           = nil

        # @!attribute ftp_timeout
        #   @return [Integer] The timeout in seconds to wait for a response to an FTP command
        attr_accessor :ftp_timeout

        validates :ftp_timeout,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1
                  }



        # (see Base#attempt_login)
        def attempt_login(credential)
          result_options = {
              credential: credential
          }

          begin
            success = connect_login(credential.public, credential.private)
          rescue ::EOFError, Errno::ECONNRESET, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            success = false
          end


          if success
            result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
          elsif !(result_options.has_key? :status)
            result_options[:status] = Metasploit::Model::Login::Status::INCORRECT
          end

          result = ::Metasploit::Framework::LoginScanner::Result.new(result_options)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = 'ftp'
          result
        end

        private

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.connection_timeout ||= 30
          self.port               ||= DEFAULT_PORT
          self.max_send_size      ||= 0
          self.send_delay         ||= 0
          self.ftp_timeout        ||= 16
        end

      end

    end
  end
end
