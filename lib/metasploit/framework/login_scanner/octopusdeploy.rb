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

        def service_details
          super.merge(name: 'Octopus Deploy', resource: uri, parents: [ssl ? :https : :http])
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          @uri = '/api/users/login' if uri.nil?
          @method = 'POST' if method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
            service_name: 'Octopus Deploy',
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp',
            ssl: ssl
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
      end
    end
  end
end
