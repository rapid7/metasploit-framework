require 'metasploit/framework/login_scanner/http'
require 'json'

module Metasploit
  module Framework
    module LoginScanner

      # Buffalo Linkstation NAS login scanner
      class Buffalo < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 80
        PRIVATE_TYPES   = [ :password ]

        # Checks if the target is a Buffalo NAS device.
        # Note: probes / for the fingerprint page rather than the login endpoint
        # (/dynamic.pl) since that only responds meaningfully to POST requests.
        #
        # @return [false] if the target looks like a Buffalo NAS
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request({
            'method' => 'GET',
            'uri'    => '/'
          })

          return 'Unable to connect to the Buffalo NAS web interface' unless res
          return 'Unable to locate Buffalo NAS web interface (Is this really a Buffalo NAS?)' unless res.code == 200 && (res.body.include?('Buffalo') && res.body.include?('bufaction'))

          report_service(service_opts)

          false
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/dynamic.pl" if self.uri.nil?
          self.method = "POST" if self.method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
              credential: credential,
              **service_as_result(service_opts)
          }
          begin
            res = send_request({
              'method'=>'POST',
              'uri'=>'/dynamic.pl',
              'vars_post'=> {
                'bufaction'=>'verifyLogin',
                'user' => credential.public,
                'password'=>credential.private
                }
            })

            body = JSON.parse(res.body)
            if res && body.has_key?('success') && body['success']
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
          build_service_opts('buffalo-nas')
        end
      end
    end
  end
end
