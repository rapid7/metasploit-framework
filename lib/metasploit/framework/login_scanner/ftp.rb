require 'metasploit/framework/ftp/client'
require 'metasploit/framework/login_scanner/base'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with FTP.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class FTP
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::Ftp::Client

        # @!attribute ftp_timeout
        #   @return [Fixnum] The timeout in seconds to wait for a response to an FTP command
        attr_accessor :ftp_timeout
        # @!attribute max_send_size
        #   @return [Fixnum] The max size of the data to encapsulate in a single packet
        attr_accessor :max_send_size
        # @!attribute send_delay
        #   @return [Fixnum] The delay between sending packets
        attr_accessor :send_delay
        # @!attribute ssl
        #   @return [Boolean] Whether the socket should use ssl
        attr_accessor :ssl
        # @!attribute ssl_version
        #   @return [String] The version of SSL to implement
        attr_accessor :ssl_version

        validates :ftp_timeout,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1
                  }

        validates :max_send_size,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
                  }

        validates :send_delay,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
                  }

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              private: credential.private,
              public: credential.public,
              realm: nil
          }

          begin
            success = connect_login(credential.public, credential.private)
          rescue ::EOFError,  Rex::AddressInUse, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error
            result_options[:status] = :connection_error
            success = false
          end


          if success
            result_options[:status] = :success
          elsif !(result_options.has_key? :status)
            result_options[:status] = :failed
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)

        end

        private

        def chost
          '0.0.0.0'
        end

        def cport
          0
        end

        def rhost
          host
        end

        def rport
          port
        end

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.max_send_size = 0 if self.max_send_size.nil?
          self.send_delay = 0 if self.send_delay.nil?
          self.ftp_timeout = 16 if self.ftp_timeout.nil?
        end

      end

    end
  end
end
