
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class HttpPostBruteforce < HTTP

        DEFAULT_PORT  = 80
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name


        # Checks if the target is DVWA.
        #
        # @return [Boolean] TrueClass if target is DVWA, otherwise FalseClass
        def check_setup
          login_uri = normalize_uri("#{uri}/login.php")
          res = send_request({'uri'=> login_uri})

          if res && res.body.include?('Damn Vulnerable Web Application')
            return true
          end

          false
        end


        # Returns the latest sid from Symantec Web Gateway.
        #
        # @return [String] The PHP Session ID for Symantec Web Gateway login
        def get_last_sid
          @last_sid ||= lambda {
            # We don't have a session ID. Well, let's grab one right quick from the login page.
            # This should probably only happen once (initially).
            login_uri = normalize_uri("#{uri}/login.php")
            res = send_request({'uri' => login_uri})

            return '' unless res

            cookies = res.get_cookies
            @last_sid = cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
          }.call
        end

        def extract_csrf_token_and_getlastsid(path:, regex:)
          res = send_request({ 
            'method' => 'GET',
            'uri' => path,
            'keep_cookies' => true
          })

          @last_sid = lambda {
            cookies = res.get_cookies
            @last_sid = cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
          }.call
          # puts "token http response ----- : #{res.body}"
          
          if res.nil? || res.body.nil?
            raise HttpClientException, 'Empty response. Please validate RHOST'
          elsif res.code != 200
            raise HttpClientException, "Unexpected HTTP #{res.code} response."
          end

          token = res.body[regex]
          # puts "token ======= #{token}"
          if token.nil?
            puts "Cant Find token"
          end

          return @last_sid, token
        end


        # Actually doing the login. Called by #attempt_login
        #
        # @param username [String] The username to try
        # @param password [String] The password to try
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def get_login_state(credential, username, password)
          # Prep the data needed for login
          # sid       = get_last_sid
          protocol  = ssl ? 'https' : 'http'
          peer      = "#{host}:#{port}"
          login_uri = normalize_uri("#{uri}/login.php")
          sid, csrf_token = extract_csrf_token_and_getlastsid(
            path: login_uri,
            regex: %r{\w{32}}
          )
          # puts "http_post, URI = #{uri}"
          # puts "http_post, Login URI = #{login_uri}"
          # puts "http_post, host = #{host} & port = #{port} & protocol = #{protocol}"
          # puts "http_post, token = #{csrf_token}"
          res = send_request({
            'uri' => login_uri,
            'method' => 'POST',
            'host' => host,
            'rport' => port,
            'credential' => credential,
            'cookie' => sid,
            'headers' => {
              'Referer' => "#{protocol}://#{peer}/#{login_uri}"
            },
            'vars_post' => {
              'username' => username,
              'password' => password,
              'Login' => 'Login',
              'user_token' => csrf_token
            }
          })

          # puts "http_post username = #{username} and password = #{password} and user_token = #{csrf_token} and session_id = #{sid}"

          unless res
            return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
          end

          # After login, the application should give us a new SID
          cookies = res.get_cookies
          sid = cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
          @last_sid = sid # Update our SID
          
          #puts "Code = #{res.code}"
          #puts "Description : #{res.to_s}"

          # puts "Http Response = ----- CODE = #{res.code} && Location = #{res.headers['Location']}"
          if res && res.code == 302 && res.headers['Location'].include?('index.php')
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.to_s}
          end
          # puts "Http Response = ----- CODE = #{res.code} && Location = #{res.headers['Location']}"

          {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
        end


        # Attempts to login to Symantec Web Gateway. This is called first.
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
            result_opts.merge!(get_login_state(credential, credential.public, credential.private))
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
