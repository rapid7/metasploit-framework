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

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              credential: credential
          }

          begin
            # Make our initial socket to the target
            disconnect if self.sock
            connect

            # Create our VNC client overtop of the socket
            vnc = Rex::Proto::RFB::Client.new(sock, :allow_none => false)


            if vnc.handshake
              if vnc_auth(vnc,credential.private)
                result_options[:status] = :success
              else
                result_options.merge!({
                  status: :failed,
                  proof: vnc.error
                })
              end
            else
              result_options.merge!({
                status: :connection_error,
                proof: vnc.error
              })
            end
          rescue ::EOFError,  Rex::AddressInUse, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error => e
            result_options.merge!({
                status: :connection_error,
                proof: e.message
            })
          end
          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        private

        # This method checks the VNC error to see if we should wait and retry
        # @param error [String] The VNC error message received
        # @return [Boolean] whether or not we should attempt the retry
        def retry?(error)
          return true if error =~ /connection has been rejected/ # UltraVNC
          return true if error =~ /Too many security failures/ # vnc4server
          false
        end

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.max_send_size = 0 if self.max_send_size.nil?
          self.send_delay = 0 if self.send_delay.nil?
        end

        # This method attempts the actual VNC authentication. It has built in retries to handle
        # delays built into the VNC RFB authentication.
        # @param client [Rex::Proto::RFB::Client] The VNC client object to authenticate through
        # @param password [String] the password to attempt the authentication with
        def vnc_auth(client,password)
          success = false
          5.times do |n|
            if client.authenticate(password)
              success = true
              break
            end
            break unless retry?(client.error)

            # Wait for an increasing ammount of time before retrying
            delay = (2**(n+1)) + 1
            select(nil, nil, nil, delay)
          end
          success
        end
      end

    end
  end
end