require 'metasploit/framework/tcp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner
      # This is the LoginScanner class for dealing with DB2 Database servers.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class DB2
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        DEFAULT_PORT         = 50000
        DEFAULT_REALM        = 'toolsdb'
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        # @todo XXX
        LIKELY_SERVICE_NAMES = [ ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = Metasploit::Model::Realm::Key::DB2_DATABASE

        # @see Base#attempt_login
        def attempt_login(credential)
          result_options = {
              credential: credential
          }

          begin
            probe_data = send_probe(credential.realm)

            if probe_data.empty?
              result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            else
              if authenticate?(credential)
                result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
              else
                result_options[:status] = Metasploit::Model::Login::Status::INCORRECT
              end
            end
          rescue ::Rex::ConnectionError, ::Rex::Proto::DRDA::RespError, ::Timeout::Error => e
            result_options.merge!({
              status:  Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e,
            })
          end

          result = ::Metasploit::Framework::LoginScanner::Result.new(result_options)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = 'db2'
          result
        end

        private
        # This method takes the credential and actually attempts the authentication
        # @param credential [Credential] The Credential object to authenticate with.
        # @return [Boolean] Whether the authentication was successful
        def authenticate?(credential)
          # Send the login packet and get a response packet back
          login_packet = Rex::Proto::DRDA::Utils.client_auth(:dbname => credential.realm,
            :dbuser => credential.public,
            :dbpass => credential.private
          )
          sock.put login_packet
          response = sock.get_once
          if valid_response?(response)
            if successful_login?(response)
              true
            else
              false
            end
          else
            false
          end
        end

        # This method opens a socket to the target DB2 server.
        # It then sends a client probe on that socket to get information
        # back on the server.
        # @param database_name [String] The name of the database to probe
        # @return [Hash] A hash containing the server information from the probe reply
        def send_probe(database_name)
          disconnect if self.sock
          connect

          probe_packet = Rex::Proto::DRDA::Utils.client_probe(database_name)
          sock.put probe_packet
          response = sock.get_once

          response_data = {}
          if valid_response?(response)
            packet = Rex::Proto::DRDA::SERVER_PACKET.new.read(response)
            response_data = Rex::Proto::DRDA::Utils.server_packet_info(packet)
          end
          response_data
        end

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.connection_timeout ||= 30
          self.port               ||= DEFAULT_PORT
          self.max_send_size      ||= 0
          self.send_delay         ||= 0

          self.ssl = false if self.ssl.nil?
        end

        # This method takes a response packet and checks to see
        # if the authentication was actually successful.
        #
        # @param response [String] The unprocessed response packet
        # @return [Boolean] Whether the authentication was successful
        def successful_login?(response)
          packet = Rex::Proto::DRDA::SERVER_PACKET.new.read(response)
          packet_info = Rex::Proto::DRDA::Utils.server_packet_info(packet)
          if packet_info[:db_login_success]
            true
          else
            false
          end
        end

        # This method provides a simple test on whether the response
        # packet was valid.
        #
        # @param response [String] The response to examine from the socket
        # @return [Boolean] Whether the response is valid
        def valid_response?(response)
          response && response.length > 0
        end
      end

    end
  end
end
