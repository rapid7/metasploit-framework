require 'metasploit/framework/login_scanner/base'

module Metasploit
  module Framework
    module LoginScanner

      # Kerberos User scanner
      class Kerberos
        include Metasploit::Framework::LoginScanner::Base
        include Msf::Exploit::Remote::Kerberos::Client

        DEFAULT_PORT = 88

        def attempt_login(credential)
          request_options = {
            credential: credential,
            host: self.host,
            port: self.port,
            protocol: 'tcp',
            service_name: 'kerberos'
          }

          begin
            res = send_request_as(request_options.merge({
              timeout: self.timeout,
              client_name: credential.to_h[:username],
              server_name: self.server_name,
              realm: self.realm,
              pa_data: self.pa_data
            }))
          rescue ::EOFError => e
            elog(e)
            # Stop further requests entirely
            res_opts = request_options.merge({ status: :eof, proof: e })
            return Metasploit::Framework::LoginScanner::Result.new(res_opts)
          rescue Rex::Proto::Kerberos::Model::Error::KerberosDecodingError => e
            elog(e)
            # Stop further requests entirely
            res_opts = request_options.merge({ status: :decode_error, proof: e })
            return Metasploit::Framework::LoginScanner::Result.new(res_opts)
          end

          case res.msg_type
          when Rex::Proto::Kerberos::Model::AS_REP
            hash = format_asrep_to_john_hash(res)

            # Accounts that have 'Do not require Kerberos preauthentication' enabled, will receive an ASREP response with a ticket present
            res_opts = request_options.merge({ status: :no_preauth, hash: hash, proof: res.msg_type })
            return Metasploit::Framework::LoginScanner::Result.new(res_opts)
          when Rex::Proto::Kerberos::Model::KRB_ERROR
            if res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_REQUIRED
              res_opts = request_options.merge({ status: :present, proof: res.msg_type })
              return Metasploit::Framework::LoginScanner::Result.new(res_opts)
            elsif res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED
              res_opts = request_options.merge({ status: :disabled_or_locked_out, proof: res.msg_type })
              return Metasploit::Framework::LoginScanner::Result.new(res_opts)
            elsif res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN
              res_opts = request_options.merge({ status: :not_found, proof: res.msg_type })
              return Metasploit::Framework::LoginScanner::Result.new(res_opts)
            elsif res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_WRONG_REALM
              # Stop further requests entirely
              res_opts = request_options.merge({ status: :wrong_realm, proof: res.msg_type })
              return Metasploit::Framework::LoginScanner::Result.new(res_opts)
            else
              res_opts = request_options.merge({ status: :unknown_error, proof: res.error_code })
              return Metasploit::Framework::LoginScanner::Result.new(res_opts)
            end
          else
            res_opts = request_options.merge({ status: :unknown_response, proof: { error_code: res.error_code, response: res.msg_type.inspect } })
            return Metasploit::Framework::LoginScanner::Result.new(res_opts)
          end
        end

        def scan!
          cred_details.each do |credential|
            result = attempt_login(credential)
            result.freeze

            yield result if block_given?
          end
        end

        attr_accessor :server_name, :realm, :pa_data, :datastore

        private

        def set_sane_defaults
          self.port = DEFAULT_PORT unless self.port
        end
      end
    end
  end
end
