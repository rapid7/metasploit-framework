require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class DVWA < HTTP

        DEFAULT_PORT  = 80
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name

        # Checks if the target is Damn Vulnerable Web Application. The login module should call this.
        #
        # @return [Boolean] TrueClass if target is DVWA, otherwise FalseClass
        def check_valid_login
          login_uri = "#{uri}login.php"
          res = send_request({'uri'=> login_uri})

          if res.body.include?('Damn Vulnerable Web Application')
            return true
          end

          false
        end

        # Returns the latest sid from DVWA.
        #
        # @return [String] The PHP Session ID for DVWA login
        def get_last_sid
          login_uri = "#{uri}login.php"
          res = send_request({'uri'=> login_uri})
          sid = res.get_cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
          return sid
        end

        # Actually doing the login. Called by #attempt_login
        #
        # @param username [String] The username to try
        # @param password [String] The password to try
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def get_login_state(username, password)
          # Prep the data needed for login
          sid    = get_last_sid
          protocol  = ssl ? 'https' : 'http'
          peer      = "#{host}:#{port}"
          login_uri = "#{uri}login.php"
          valid_uri = "#{uri}index.php"
          # Grabs CSRF token for POST request
          tknres = send_request({
            'uri' => login_uri,
            'method' => 'GET',
            'cookie' => sid,
            'headers' => {
            },
            'vars_post' => {
            }
          })
          utoken = tknres.body.scan(/([a-f0-9]{32})/).flatten[0] || ''
          #Sends POST request with valid sid and token
          postres = send_request({
            'uri' => login_uri,
            'method' => 'POST',
            'cookie' => sid,
            'headers' => {
            'Referer' => "#{protocol}://#{peer}/#{login_uri}"
            },
            'vars_post' => {
              'username' => username,
              'password' => password,
              'Login' => 'Login', # Found in the HTML form
              'user_token' => utoken
            }
          })
          #Requests homepage and checks if login is valid
            res = send_request({
            'uri' => valid_uri,
            'method' => 'GET',
            'cookie' => sid,
            'headers' => {
            },
            'vars_post' => {
            }
          })
          if res.body.include?('You have logged in as')
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.to_s}
          end

          {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
         end


        # Attempts to login to DVWA. This is called first.
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
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

