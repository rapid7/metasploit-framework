require 'metasploit/framework/tcp/client'
require 'rbmysql'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

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

            ::RbMysql.connect({
              :host          => host,
              :port          => port,
              :read_timeout  => 300,
              :write_timeout => 300,
              :socket        => sock,
              :user          => credential.public,
              :password      => credential.private,
              :db            => ''
            })

          rescue ::SystemCallError, Rex::ConnectionError => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          rescue RbMysql::ClientError => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          rescue RbMysql::HostNotPrivileged => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          rescue RbMysql::AccessDeniedError => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::INCORRECT,
              proof: e
            })
          rescue RbMysql::HostIsBlocked => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e
            })
          end

          unless result_options[:status]
            result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
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
