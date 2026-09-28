require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # GL.iNet Router LuCI interface login scanner
      class GLiNet < HTTP
        # Inherit LIKELY_PORTS, LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = false
        DEFAULT_PORT = 80
        PRIVATE_TYPES = [:password]

        # Checks if the target is a GL.iNet router with LuCI interface
        #
        # @return [false] if the target looks like GL.iNet LuCI
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          # Try to access the login page
          res = send_request({
            'method' => 'GET',
            'uri' => uri
          })

          return 'Unable to connect to the target' unless res
          return 'Target does not appear to be a GL.iNet LuCI interface (no authentication prompt)' unless res.code == 403 || res.code == 200

          # Check for LuCI-specific indicators in the response
          if res.body.include?('LuCI') || res.body.include?('GL.iNet') || res.body.include?('luci_username')
            report_service(service_opts)
            return false
          end

          'Target does not appear to be a GL.iNet LuCI interface'
        end

        def service_opts
          build_service_opts('glinet-luci')
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = '/cgi-bin/luci' if uri.nil?
          self.method = 'POST' if method.nil?

          super
        end

        # Attempts to login to GL.iNet LuCI interface
        #
        # @param credential [Metasploit::Framework::Credential] The credential to attempt
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            **service_as_result(service_opts)
          }

          begin
            # Build the login request
            protocol = ssl ? 'https' : 'http'
            peer = "#{host}:#{port}"
            login_uri = uri

            res = send_request({
              'method' => 'POST',
              'uri' => login_uri,
              'headers' => {
                'Origin' => "#{protocol}://#{peer}",
                'Referer' => "#{protocol}://#{peer}#{login_uri}"
              },
              'vars_post' => {
                'luci_username' => credential.public,
                'luci_password' => credential.private
              }
            })

            # GL.iNet LuCI returns HTTP 302 on successful login, 403 on failure
            if res && res.code == 302
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.headers)
            elsif res
              result_opts.merge!(proof: res.to_s)
            end
          rescue Rex::ConnectionError => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e.message)
          end

          Result.new(result_opts)
        end
      end
    end
  end
end
