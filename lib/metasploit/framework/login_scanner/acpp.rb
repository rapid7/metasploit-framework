require 'metasploit/framework/tcp/client'
require 'rex/proto/acpp'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner
      # This is the LoginScanner class for dealing with the Apple Airport ACPP
      # protocol.  It is responsible for taking a single target, and a list of
      # credentials and attempting them. It then saves the results.
      class ACPP
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        #
        # CONSTANTS
        #
        DEFAULT_PORT         = Rex::Proto::ACPP::DEFAULT_PORT
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'acpp' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = nil


        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              credential: credential,
              host: host,
              port: port,
              protocol: 'tcp',
              service_name: 'acpp'
          }

          begin
            # Make our initial socket to the target
            disconnect if self.sock
            connect

            client = Rex::Proto::ACPP::Client.new(sock)

            auth_response = client.authenticate(credential.private)
            if auth_response.successful?
              status = Metasploit::Model::Login::Status::SUCCESSFUL
            else
              status = Metasploit::Model::Login::Status::INCORRECT
            end
            result_options.merge!(
              proof: "Status code #{auth_response.status}",
              status: status
            )
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
      end
    end
  end
end
