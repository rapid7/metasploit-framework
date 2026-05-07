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

        public :banner

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
            ftpsock = connect(true)
            res = send_user(credential.public, ftpsock)
            res = send_pass(credential.private, ftpsock) if res =~ /^(331|2)/
            result_options[:proof] = res.to_s.strip
            result_options[:status] = if res.nil?
                                        Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
                                      elsif res.start_with?('2')
                                        Metasploit::Model::Login::Status::SUCCESSFUL
                                      else
                                        Metasploit::Model::Login::Status::INCORRECT
                                      end
          rescue ::EOFError, Errno::ECONNRESET, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          ensure
            disconnect
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
