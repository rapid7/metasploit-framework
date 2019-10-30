
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class ManageEngineDesktopCentral < HTTP

        DEFAULT_PORT  = 8020
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name


        # Checks if the target is ManageEngine Dekstop Central.
        #
        # @return [Boolean] TrueClass if target is MSP, otherwise FalseClass
        def check_setup
          login_uri = normalize_uri("#{uri}/configurations.do")
          res = send_request({'uri' => login_uri})

          if res && res.body.include?('ManageEngine Desktop Central')
            return true
          end

          false
        end


        # Returns the latest sid from MSP
        #
        # @param res [Rex::Proto::Http::Response] 
        # @return [String] The session ID for MSP
        def get_sid(res)
          cookies = res.get_cookies
          sid = cookies.scan(/(DCJSESSIONID=\w+);*/).flatten[0] || ''
          sid
        end



        # Returns the hidden inputs
        #
        # @param res [Rex::Proto::Http::Response]
        # @return [Hash] Input fields
        def get_hidden_inputs(res)
          found_inputs = {}
          res.body.scan(/(<input type="hidden" .+>)/).flatten.each do |input|
            name  = input.scan(/name="(\w+)"/).flatten[0] || ''
            value = input.scan(/value="([\w\.\-]+)"/).flatten[0] || ''
            found_inputs[name] = value
          end
          found_inputs
        end


        # Returns all the items needed to login
        #
        # @return [Hash] Login items
        def get_required_login_items
          items = {}
          login_uri = normalize_uri("#{uri}/configurations.do")
          res = send_request({'uri' => login_uri})
          return items unless res
          items.merge!({'sid' => get_sid(res)})
          items.merge!(get_hidden_inputs(res))
          items
        end


        # Actually doing the login. Called by #attempt_login
        #
        # @param username [String] The username to try
        # @param password [String] The password to try
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def get_login_state(username, password)
          login_uri = normalize_uri("#{uri}/j_security_check")
          login_items = get_required_login_items

          res = send_request({
            'uri' => login_uri,
            'method' => 'POST',
            'cookie' => login_items['sid'],
            'vars_post' => {
              'j_username' => username,
              'j_password' => password,
              'Button' => 'Sign+in',
              'buildNum' => login_items['buildNum'],
              'clearCacheBuildNum' => login_items['clearCacheBuildNum']
            }
          })

          unless res
            return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
          end

          if res.code == 302
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.to_s}
          end

          {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
        end


        # Attempts to login to MSP.
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: LOGIN_STATUS::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          begin
            result_opts.merge!(get_login_state(credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            # Something went wrong during login. 'e' knows what's up.
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          Result.new(result_opts)
        end

      end
    end
  end
end

