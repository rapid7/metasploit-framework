require 'metasploit/framework/login_scanner/base'

module Metasploit
  module Framework
    module LoginScanner

      # Kerberos User scanner
      class Kerberos
        include Metasploit::Framework::LoginScanner::Base
        include Msf::Exploit::Remote::Kerberos::Client

        DEFAULT_PORT = 88
        REALM_KEY = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
        DEFAULT_REALM = nil

        def attempt_login(credential)
          result_options = {
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp',
            service_name: 'kerberos'
          }

          begin
            res = send_request_tgt(
              server_name: server_name,
              client_name: credential.public,
              password: credential.private,
              realm: credential.realm
            )

            result_options = result_options.merge(
              {
                status: Metasploit::Model::Login::Status::SUCCESSFUL,
                proof: res
              }
            )
            return Metasploit::Framework::LoginScanner::Result.new(result_options)
          rescue ::EOFError => e
            result_options = result_options.merge({ status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e })
            return Metasploit::Framework::LoginScanner::Result.new(result_options)
          rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
            status = status_for_error_code(e.error_code)
            result_options = result_options.merge({ status: status, proof: e })
            return Metasploit::Framework::LoginScanner::Result.new(result_options)
          end
        end

        attr_accessor :server_name

        # Override the kerberos client's methods with the login scanner implementations
        alias rhost host
        alias rport port
        alias timeout connection_timeout

        private

        def status_for_error_code(error_code)
          map = {
            # This might be because of an explicit disabling or because of other restrictions in place on the account. For example: account disabled, expired, or locked out
            # Note this doesn't map cleanly to Metasploit's login status codes which are only DISABLED or DENIED_ACCESS, and not a union
            Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED => Metasploit::Model::Login::Status::DISABLED,

            # The username doesn't exist
            Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN => Metasploit::Model::Login::Status::INVALID_PUBLIC_PART
          }

          map.fetch(error_code, Metasploit::Model::Login::Status::INCORRECT)
        end

        def set_sane_defaults
          self.port = DEFAULT_PORT unless self.port
        end

        def print_status(*args)
          framework_module.print_status(*args) if framework_module
        end

        def print_good(*args)
          framework_module.print_good(*args) if framework_module
        end

        def vprint_status(*args)
          framework_module.vprint_status(*args) if framework_module
        end
      end
    end
  end
end
