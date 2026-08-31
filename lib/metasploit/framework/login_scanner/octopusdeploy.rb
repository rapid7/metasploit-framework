require 'metasploit/framework/login_scanner/http'
require 'json'

module Metasploit
  module Framework
    module LoginScanner

      # Octopus Deploy login scanner
      class OctopusDeploy < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 80
        PRIVATE_TYPES   = [ :password ]

        # Checks if the target is an Octopus Deploy server
        #
        # @return [false] if the target looks like Octopus Deploy
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request({
            'method' => 'GET',
            'uri'    => '/api'
          })

          return 'Unable to connect to the Octopus Deploy API' unless res
          return 'Unable to locate Octopus Deploy API (Is this really Octopus Deploy?)' unless res.code == 200 && res.body.include?('OctopusDeploy')

          report_service(service_opts)

          false
        end

        def service_opts
          build_service_opts('octopusdeploy')
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          uri = '/api/users/login' if uri.nil?
          method = 'POST' if method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            **service_as_result(service_opts)
          }
          begin
            json_post_data = JSON.pretty_generate({ Username: credential.public, Password: credential.private })
            res = send_request({
              'method' => 'POST',
              'uri' => uri,
              'ctype' => 'application/json',
              'data' => json_post_data
            })

            body = JSON.parse(res.body)
            if res && res.code == 200 && body.key?('IsActive') && body['IsActive']
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.body)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end
          rescue ::JSON::ParserError
            result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res.body)
          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
          end
          Result.new(result_opts)
        end

        def service_opts
          build_service_opts('octopusdeploy')
        end
      end
    end
  end
end
