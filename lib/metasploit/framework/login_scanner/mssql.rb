require 'rex/proto/mssql/client'
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

        DEFAULT_PORT         = 1433
        DEFAULT_REALM         = 'WORKSTATION'
        # Lifted from lib/msf/core/exploit/mssql.rb
        LIKELY_PORTS         = [ 1433, 1434, 1435, 14330, 2533, 9152, 2638 ]
        # Lifted from lib/msf/core/exploit/mssql.rb
        LIKELY_SERVICE_NAMES = [ 'ms-sql-s', 'ms-sql2000', 'sybase', 'mssql' ]
        PRIVATE_TYPES        = [ :password, :ntlm_hash ]
        REALM_KEY           = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN

        # @!attribute auth
        #   @return [Array<String>] Auth The Authentication mechanism to use
        #   @see Msf::Exploit::Remote::AuthOption::MSSQL_OPTIONS
        attr_accessor :auth

        validates :auth,
                  inclusion: { in: Msf::Exploit::Remote::AuthOption::MSSQL_OPTIONS }

        validates :auth,
                  inclusion: { in: Msf::Exploit::Remote::AuthOption::MSSQL_OPTIONS }

        # @!attribute domain_controller_rhost
        #   @return [String] Auth The domain controller rhost, required for Kerberos Authentication
        attr_accessor :domain_controller_rhost

        # @!attribute domain_controller_rhost
        #   @return [String] Auth The mssql hostname, required for Kerberos Authentication
        attr_accessor :hostname

        # @!attribute windows_authentication
        #   @return [Boolean] Whether to use Windows Authentication instead of SQL Server Auth.
        attr_accessor :windows_authentication

        # @!attribute use_client_as_proof
        #   @return [Boolean] If a login is successful and this attribute is true - an MSSQL::Client instance is used as proof
        attr_accessor :use_client_as_proof

        # @!attribute max_send_size
        #   @return [Integer] The max size of the data to encapsulate in a single packet
        attr_accessor :max_send_size

        # @!attribute send_delay
        #   @return [Integer] The delay between sending packets
        attr_accessor :send_delay

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
            client = Rex::Proto::MSSQL::Client.new(framework_module, framework, host, port, proxies, sslkeylogfile: sslkeylogfile)
            if client.mssql_login(credential.public, credential.private, '', credential.realm)
              result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
              if use_client_as_proof
                result_options[:proof] = client
                result_options[:connection] = client.sock
              else
                client.disconnect
              end
            else
              result_options[:status] = Metasploit::Model::Login::Status::INCORRECT
            end
          rescue ::Rex::ConnectionError => e
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            result_options[:proof] = e
          rescue => e
            elog(e)
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            result_options[:proof] = e
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
          self.auth                   = Msf::Exploit::Remote::AuthOption::AUTO if self.auth.nil?
          self.windows_authentication = false if self.windows_authentication.nil?
          self.tdsencryption          = false if self.tdsencryption.nil?
        end
      end

    end
  end
end
