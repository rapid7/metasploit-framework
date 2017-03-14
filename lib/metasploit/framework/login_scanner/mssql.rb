require 'metasploit/framework/mssql/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/login_scanner/ntlm'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Microsoft SQL Servers.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results
      class MSSQL
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::LoginScanner::NTLM
        include Metasploit::Framework::MSSQL::Client

        DEFAULT_PORT         = 1433
        DEFAULT_REALM         = 'WORKSTATION'
        # Lifted from lib/msf/core/exploit/mssql.rb
        LIKELY_PORTS         = [ 1433, 1434, 1435, 14330, 2533, 9152, 2638 ]
        # Lifted from lib/msf/core/exploit/mssql.rb
        LIKELY_SERVICE_NAMES = [ 'ms-sql-s', 'ms-sql2000', 'sybase', 'mssql' ]
        PRIVATE_TYPES        = [ :password, :ntlm_hash ]
        REALM_KEY           = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN

        # @!attribute windows_authentication
        #   @return [Boolean] Whether to use Windows Authentication instead of SQL Server Auth.
        attr_accessor :windows_authentication

        validates :windows_authentication,
          inclusion: { in: [true, false] }

        attr_accessor :tdsencryption

        validates :tdsencryption,
          inclusion: { in: [true, false] }

        def attempt_login(credential)
          result_options = {
              credential: credential,
              host: host,
              port: port,
              protocol: 'tcp',
              service_name: 'mssql'
          }

          begin
            if mssql_login(credential.public, credential.private, '', credential.realm)
              result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
            else
              result_options[:status] = Metasploit::Model::Login::Status::INCORRECT
            end
          rescue ::Rex::ConnectionError
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        private

        def set_sane_defaults
          self.connection_timeout    ||= 30
          self.port                  ||= DEFAULT_PORT
          self.max_send_size         ||= 0
          self.send_delay            ||= 0

          # Don't use ||= with booleans
          self.send_lm                = true if self.send_lm.nil?
          self.send_ntlm              = true if self.send_ntlm.nil?
          self.send_spn               = true if self.send_spn.nil?
          self.use_lmkey              = false if self.use_lmkey.nil?
          self.use_ntlm2_session      = true if self.use_ntlm2_session.nil?
          self.use_ntlmv2             = true if self.use_ntlmv2.nil?
          self.windows_authentication = false if self.windows_authentication.nil?
          self.tdsencryption          = false if self.tdsencryption.nil?
        end
      end

    end
  end
end
