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
            unless res.preauth_required
              # Pre-auth not required - let's get an RC4-HMAC ticket, since it's more easily crackable
              begin
                res = send_request_tgt(
                  server_name: server_name,
                  client_name: credential.public,
                  password: credential.private,
                  realm: credential.realm,
                  offered_etypes: [Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC]
                )
              rescue Rex::Proto::Kerberos::Model::Error::KerberosEncryptionNotSupported => e
                # RC4 likely disabled - let's just use the initial response
              end
            end

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
            status = self.class.login_status_for_kerberos_error(e)
            result_options = result_options.merge({ status: status, proof: e })
            return Metasploit::Framework::LoginScanner::Result.new(result_options)
          end
        end

        attr_accessor :server_name

        # Override the kerberos client's methods with the login scanner implementations
        alias rhost host
        alias rport port
        alias timeout connection_timeout

        # @param [Rex::Proto::Kerberos::Model::Error::KerberosError] krb_err The kerberos error
        def self.login_status_for_kerberos_error(krb_err)
          error_code = krb_err.error_code
          case error_code
          when Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_KEY_EXPIRED, Rex::Proto::Kerberos::Model::Error::ErrorCodes::KRB_AP_ERR_SKEW
            # Correct password, but either password needs resetting or clock is skewed
            Metasploit::Model::Login::Status::SUCCESSFUL
          when Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN
            # The username doesn't exist
            Metasploit::Model::Login::Status::INVALID_PUBLIC_PART
          when Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED
            # Locked out, disabled or expired
            # It doesn't appear to be documented anywhere, but Microsoft gives us a bit
            # of extra information in the e-data section
            begin
              pa_data_entry = krb_err.res.e_data_as_pa_data_entry
              if pa_data_entry && pa_data_entry.type == Rex::Proto::Kerberos::Model::PreAuthType::PA_PW_SALT
                pw_salt = pa_data_entry.decoded_value
                if pw_salt.nt_status
                  case pw_salt.nt_status.value
                  when ::WindowsError::NTStatus::STATUS_ACCOUNT_LOCKED_OUT
                    Metasploit::Model::Login::Status::LOCKED_OUT
                  when ::WindowsError::NTStatus::STATUS_ACCOUNT_DISABLED
                    Metasploit::Model::Login::Status::DISABLED
                  when ::WindowsError::NTStatus::STATUS_ACCOUNT_EXPIRED
                    # Actually expired, which is effectively Disabled
                    Metasploit::Model::Login::Status::DISABLED
                  else
                    # Unknown - maintain existing behaviour
                    Metasploit::Model::Login::Status::DISABLED
                  end
                else
                  Metasploit::Model::Login::Status::DISABLED
                end
              else
                  Metasploit::Model::Login::Status::DISABLED
              end
            rescue Rex::Proto::Kerberos::Model::Error::KerberosDecodingError
              # Could be a non-MS implementation?
              Metasploit::Model::Login::Status::DISABLED
            end
          else
            Metasploit::Model::Login::Status::INCORRECT
          end
        end

        private

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
