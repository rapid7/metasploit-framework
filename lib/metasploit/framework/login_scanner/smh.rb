
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # HP System Management login scanner tested on v6.3.1.24 upto v7.2.1.3 and 7.4
      class Smh < HTTP

        DEFAULT_PORT  = 4848
        PRIVATE_TYPES = [ :password ]
        CAN_GET_SESSION = true

        # Checks if the target is HP System Management Homepage
        #
        # @return [false] if the target looks like HP SMH
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request({
            'method' => 'GET',
            'uri'    => normalize_uri('/cpqlogin.htm')
          })

          return 'Unable to connect to the HP System Management Homepage login page' unless res
          return 'Unable to locate HP System Management Homepage login page (Is this really HP SMH?)' unless res.code == 200 && res.body.include?('HP System Management Homepage')

          report_service(service_opts)

          false
        end

        def service_opts
          build_service_opts('hp-smh')
        end

        # (see Base#attempt_login)
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            **service_as_result(service_opts)
          }

          req_opts = {
            'method' => 'POST',
            'uri'    => uri,
            'vars_post' => {
              'redirecturl'         => '',
              'redirectquerystring' => '',
              'user'                => credential.public,
              'password'            => credential.private
            }
          }

          res = nil

          begin
            res = send_request(req_opts)

          rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, ::EOFError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
            return Result.new(result_opts)
          end

          if res && res.headers['CpqElm-Login'].to_s =~ /success/
            result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL)
          else
            result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT)
          end

          Result.new(result_opts)
        end

        def service_opts
          build_service_opts('smh')
        end

      end
    end
  end
end
