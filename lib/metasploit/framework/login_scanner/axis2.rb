
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Tomcat Manager login scanner
      class Axis2 < HTTP

        DEFAULT_PORT = 8080
        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP

        CAN_GET_SESSION = true
        PRIVATE_TYPES   = [ :password ]

        # Checks if the target is Apache Axis2
        #
        # @return [false] if the target looks like Axis2
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request({
            'method' => 'GET',
            'uri'    => uri
          })

          return 'Unable to connect to the Axis2 login page' unless res
          return 'Unable to locate Axis2 login page (Is this really Apache Axis2?)' unless res.code == 200 && res.body.include?('axis2-admin')

          report_service(service_opts)

          false
        end

        # (see Base#attempt_login)
        def attempt_login(credential)
          result_opts = {
              credential: credential,
              **service_as_result(service_opts)
          }

          begin
            # Refactor to access Metasploit::Framework::LoginScanner::HTTP#send_request()
            # to send request to the HTTP server and obtain a response
            response = send_request({
              'uri' => uri,
              'method' => 'POST',
              'vars_post' =>
               {
                 'userName' => credential.public,
                 'password' => credential.private,
                 'submit' => '+Login+'
               }
            })

            if response && response.code == 200 && response.body.include?("upload")
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: response)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: response)
            end
          rescue ::EOFError, Rex::ConnectionError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end

          Result.new(result_opts)

        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/axis2/axis2-admin/login" if self.uri.nil?
          @method = "POST".freeze

          super
        end

        # The method *must* be "POST", so don't let the user change it
        # @raise [RuntimeError]
        def method=(_)
          raise RuntimeError, "Method must be POST for Axis2"
        end

        def service_opts
          build_service_opts('axis2')
        end

      end
    end
  end
end

