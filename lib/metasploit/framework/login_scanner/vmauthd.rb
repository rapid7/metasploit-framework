require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/tcp/client'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with vmware-auth.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class VMAUTHD
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        DEFAULT_PORT         = 902
        LIKELY_PORTS         = [ DEFAULT_PORT, 903, 912 ]
        LIKELY_SERVICE_NAMES = [ 'vmauthd', 'vmware-auth' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = nil

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attempt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            service_name: 'vmauthd',
            protocol: 'tcp'
          }

          disconnect if self.sock

          begin
            connect
            select([sock], nil, nil, 0.4)

            # Check to see if we received an OK?
            result_options[:proof] = sock.get_once
            if result_options[:proof] && result_options[:proof][/^220 VMware Authentication Daemon Version.*/]
              # Switch to SSL if required
              swap_sock_plain_to_ssl(sock) if result_options[:proof] && result_options[:proof][/SSL/]

              # If we received an OK we should send the USER
              sock.put("USER #{credential.public}\r\n")
              result_options[:proof] = sock.get_once

              if result_options[:proof] && result_options[:proof][/^331.*/]
                # If we got an OK after the username we can send the PASS
                sock.put("PASS #{credential.private}\r\n")
                result_options[:proof] = sock.get_once

                if result_options[:proof] && result_options[:proof][/^230.*/]
                  # if the pass gives an OK, we're good to go
                  result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
                end
              end
            end

          rescue Rex::ConnectionError, EOFError, Timeout::Error, Errno::EPIPE => e
            result_options.merge!(
              proof: e.message,
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            )
          end

          disconnect if self.sock

          Result.new(result_options)
        end

        private

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.connection_timeout ||= 30
          self.port               ||= DEFAULT_PORT
          self.max_send_size      ||= 0
          self.send_delay         ||= 0
        end

        def swap_sock_plain_to_ssl(nsock=self.sock)
          ctx =  generate_ssl_context
          ssl = OpenSSL::SSL::SSLSocket.new(nsock, ctx)

          ssl.connect

          nsock.extend(Rex::Socket::SslTcp)
          nsock.sslsock = ssl
          nsock.sslctx  = ctx
        end

        def generate_ssl_context
          ctx = OpenSSL::SSL::SSLContext.new(:SSLv3)
          @@cached_rsa_key ||= OpenSSL::PKey::RSA.new(1024){}

          ctx.key = @@cached_rsa_key

          ctx.session_id_context = Rex::Text.rand_text(16)

          ctx
        end
      end

    end
  end
end
