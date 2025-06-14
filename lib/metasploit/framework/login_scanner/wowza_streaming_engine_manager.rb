require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class WowzaStreamingEngineManager < HTTP

        DEFAULT_PORT = 8088
        PRIVATE_TYPES = [ :password ].freeze
        LOGIN_STATUS = Metasploit::Model::Login::Status

        # Checks if the target is Wowza Streaming Engine Manager. The login module should call this.
        #
        # @return [Boolean] TrueClass if target is Wowza Streaming Engine Manager, otherwise FalseClass
        def check_setup
          res = send_request({ 'uri' => normalize_uri('/enginemanager/login.htm') })

          return false unless res
          return false unless res.code == 200

          res.body.include?('Wowza Streaming Engine Manager')
        end

        #
        # Attempts to login to Wowza Streaming Engine server via Manager web interface
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
        #
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          res = send_request({
            'method' => 'POST',
            'uri' => normalize_uri('/enginemanager/j_spring_security_check'),
            'vars_post' => {
              'wowza-page-redirect' => '',
              'j_username' => credential.public.to_s,
              'j_password' => credential.private.to_s,
              'host' => 'http://localhost:8087'
            }
          })

          unless res
            result_opts.merge!({ status: LOGIN_STATUS::UNABLE_TO_CONNECT })
          end

          if res && res.code == 302 && res['location'].to_s.include?('Home.htm')
            cookie = res.get_cookies
            result_opts.merge!({ status: LOGIN_STATUS::SUCCESSFUL, proof: cookie.to_s }) unless cookie.blank?
          end

          Result.new(result_opts)
        end
      end
    end
  end
end
