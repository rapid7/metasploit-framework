require 'metasploit/framework/tcp/client'
require 'rex/proto/rfb'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner
      # This is the LoginScanner class for dealing with the VNC RFB protocol.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class VNC
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client


        #
        # CONSTANTS
        #

        LIKELY_PORTS         = (5900..5910).to_a
        LIKELY_SERVICE_NAMES = [ 'vnc' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = nil

        # Error indicating retry should occur for UltraVNC
        ULTRA_VNC_RETRY_ERROR = 'connection has been rejected'
        # Error indicating retry should occur for VNC 4 Server
        VNC4_SERVER_RETRY_ERROR = 'Too many security failures'
        # Known retry errors for all supported versions of VNC
        RETRY_ERRORS = [
            ULTRA_VNC_RETRY_ERROR,
            VNC4_SERVER_RETRY_ERROR
        ]

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              credential: credential,
              host: host,
              port: port,
              protocol: 'tcp',
              service_name: 'vnc'
          }

          begin
            # Make our initial socket to the target
            disconnect if self.sock
            connect

            # Create our VNC client overtop of the socket
            vnc = Rex::Proto::RFB::Client.new(sock, :allow_none => false)

            if vnc.handshake
              type = vnc.negotiate_authentication
              if type != Rex::Proto::RFB::AuthType::ARD
                credential.public = nil
              end
              if vnc_auth(vnc,type,credential.public,credential.private)
                result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
              else
                result_options.merge!(
                  proof: vnc.error,
                  status: Metasploit::Model::Login::Status::INCORRECT
                )
              end
            else
              result_options.merge!(
                proof: vnc.error,
                status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
              )
            end
          rescue ::EOFError, Errno::ENOTCONN, Rex::ConnectionError, ::Timeout::Error => e
            result_options.merge!(
                proof: e.message,
                status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            )
          ensure
            disconnect
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        private

        # Check the VNC error to see if we should wait and retry.
        #
        # @param error [String] The VNC error message received
        # @return [false] don't retry
        # @return [true] retry
        def retry?(error)
          RETRY_ERRORS.include?(error)
        end

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.connection_timeout ||= 30
          self.port               ||= 5900
          self.max_send_size      ||= 0
          self.send_delay         ||= 0
        end

        # This method attempts the actual VNC authentication. It has built in retries to handle
        # delays built into the VNC RFB authentication.
        # @param client [Rex::Proto::RFB::Client] The VNC client object to authenticate through
        # @param type [Rex::Proto::RFB::AuthType] The VNC authentication type to attempt
        # @param username [String] the username to attempt the authentication with
        # @param password [String] the password to attempt the authentication with
        def vnc_auth(client,type,username,password)
          success = false
          5.times do |n|
            if client.authenticate_with_type(type,username,password)
              success = true
              break
            end
            break unless retry?(client.error)

            # Wait for an increasing ammount of time before retrying
            delay = (2**(n+1)) + 1
            ::Rex.sleep(delay)
          end
          success
        end
      end

    end
  end
end
