require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Western Digital MyBook Live login scanner
      class MyBookLive < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 80
        PRIVATE_TYPES   = [ :password ]

        # Checks if the target is a Western Digital MyBook Live device
        #
        # @return [false] if the target looks like MyBook Live
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request({
            'method' => 'GET',
            'uri'    => uri
          })

          return 'Unable to connect to the MyBook Live login page' unless res
          return 'Unable to locate MyBook Live login page (Is this really Western Digital MyBook Live?)' unless res.code == 200 && res.body.include?('My Book Live')

          report_service(service_opts)

          false
        end

        def service_opts
          build_service_opts('mybook-live')
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = '/UI/login' if self.uri.nil?
          self.method = 'POST' if self.method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            **service_as_result(service_opts)
          }
          begin
            res = send_request({
              'method' => method,
              'uri' => uri,
              'vars_post' => {
                'data[Login][owner_name]' => 'admin',
                'data[Login][owner_passwd]' => credential.private
              }
            })

            if res && res.code == 302 && res.headers['location'] && res.headers['location'].include?('UI')
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.headers)
            elsif res.nil?
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: 'No response')
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res.headers)
            end
          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
          end
          Result.new(result_opts)
        end

        def service_opts
          build_service_opts('mybook_live')
        end
      end
    end
  end
end
