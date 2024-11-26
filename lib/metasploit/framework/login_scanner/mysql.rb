require 'metasploit/framework/tcp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'rex/proto/mysql/client'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with MySQL Database servers.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class MySQL
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        # @returns [Boolean] If a login is successful and this attribute is true - a MySQL::Client instance is used as proof,
        #   and the socket is not immediately closed
        attr_accessor :use_client_as_proof

        DEFAULT_PORT         = 3306
        LIKELY_PORTS         = [3306]
        LIKELY_SERVICE_NAMES = ['mysql']
        PRIVATE_TYPES        = [:password]
        REALM_KEY            = nil

        def attempt_login(credential)
          result_options = {
            credential:   credential,
            host:         host,
            port:         port,
            protocol:     'tcp',
            service_name: 'mysql'
          }

          begin
            # manage our behind the scenes socket. Close any existing one and open a new one
            disconnect if self.sock
            connect

            mysql_conn = ::Rex::Proto::MySQL::Client.connect(host, credential.public, credential.private, '', port, io: self.sock)

          rescue ::SystemCallError, Rex::ConnectionError => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          rescue Rex::Proto::MySQL::Client::ClientError => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          rescue Rex::Proto::MySQL::Client::HostNotPrivileged => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          rescue Rex::Proto::MySQL::Client::AccessDeniedError => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::INCORRECT,
              proof: e
            })
          rescue Rex::Proto::MySQL::Client::HostIsBlocked => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          end

          if mysql_conn
            result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL

            # This module no long owns the socket, return it as proof so the calling context can perform additional operations
            # Additionally assign values to nil to avoid closing the socket etc automatically
            if use_client_as_proof
              result_options[:proof] = mysql_conn
              result_options[:connection] = self.sock
              self.sock = nil
            else
              mysql_conn.close
            end
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
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
