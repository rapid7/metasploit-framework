require 'metasploit/framework/tcp/client'
require 'rex/proto/mqtt'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner
      # This is the LoginScanner class for dealing with MQTT.
      # It is responsible for taking a single target, and a list of
      # credentials and attempting them. It then saves the results.
      class MQTT
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        #
        # CONSTANTS
        #
        DEFAULT_PORT         = Rex::Proto::MQTT::DEFAULT_PORT
        DEFAULT_SSL_PORT     = Rex::Proto::MQTT::DEFAULT_SSL_PORT
        LIKELY_PORTS         = [ DEFAULT_PORT, DEFAULT_SSL_PORT ]
        LIKELY_SERVICE_NAMES = [ 'MQTT' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = nil

        # @!attribute read_timeout
        #   @return [int] The timeout use while reading responses from MQTT, in seconds
        attr_accessor :read_timeout

        # @!attribute client_id
        #   @return [String] The client identifier to use when connecting to MQTT
        attr_accessor :client_id

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              credential: credential,
              host: host,
              port: port,
              protocol: 'tcp',
              service_name: 'MQTT'
          }

          begin
            # Make our initial socket to the target
            disconnect if self.sock
            connect

            client_opts = {
              username: credential.public,
              password: credential.private,
              read_timeout: read_timeout,
              client_id: client_id
            }
            client = Rex::Proto::MQTT::Client.new(sock, client_opts)
            connect_res = client.connect
            client.disconnect

            if connect_res.return_code == 0
              status = Metasploit::Model::Login::Status::SUCCESSFUL
              proof = "Successful Connection (Received CONNACK packet)"
            else
              status = Metasploit::Model::Login::Status::INCORRECT
              proof = "Failed Connection (#{connect_res.return_code})"
            end

            result_options.merge!(
              proof: proof,
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
