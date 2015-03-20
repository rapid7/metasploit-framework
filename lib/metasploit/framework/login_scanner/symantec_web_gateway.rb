
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class SymantecWebGateway < HTTP

        DEFAULT_PORT  = 443
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name


        # Checks if the target is Symantec Web Gateway. The login module should call this.
        #
        # @return [Boolean] TrueClass if target is SWG, otherwise FalseClass
        def check_setup
          login_uri = normalize_uri("#{uri}/spywall/login.php")
          res = send_request({'uri'=> login_uri})

          if res && res.body.include?('Symantec Web Gateway')
            return true
          end

          false
        end


        # Sends a HTTP request with Rex
        #
        # @param (see Rex::Proto::Http::Request#request_raw)
        # @raise [Rex::ConnectionError] Something has gone wrong while sending the HTTP request
        # @return [Rex::Proto::Http::Response] The HTTP response
        def send_request(opts)
          res = nil
          cli = Rex::Proto::Http::Client.new(host, port,
            {
              'Msf' => framework,
              'MsfExploit' => framework_module
            },
            ssl,
            ssl_version,
            proxies
          )
          configure_http_client(cli)
          begin
            cli.connect
            req = cli.request_cgi(opts)
            res = cli.send_recv(req)
          rescue ::Errno::EPIPE, ::Timeout::Error => e
            # We are trying to mimic the same type of exception rescuing in
            # Msf::Exploit::Remote::HttpClient. But instead of returning nil, we'll consistently
            # raise Rex::ConnectionError so the #attempt_login can return the error message back
            # to the login module.
            raise Rex::ConnectionError, e.message
          ensure
            cli.close
          end

          res
        end


        # Returns the latest sid from Symantec Web Gateway.
        #
        # @returns [String] The PHP Session ID for Symantec Web Gateway login
        def get_last_sid
          @last_sid ||= lambda {
            # We don't have a session ID. Well, let's grab one right quick from the login page.
            # This should probably only happen once (initially).
            login_uri = normalize_uri("#{uri}/spywall/login.php")
            res = send_request({'uri' => login_uri})

            return '' unless res

            cookies = res.get_cookies
            @last_sid = cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
          }.call
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
          sid       = get_last_sid
          protocol  = ssl ? 'https' : 'http'
          peer      = "#{host}:#{port}"
          login_uri = normalize_uri("#{uri}/spywall/login.php")

          res = send_request({
            'uri' => login_uri,
            'method' => 'POST',
            'cookie' => sid,
            'headers' => {
              'Referer' => "#{protocol}://#{peer}/#{login_uri}"
            },
            'vars_post' => {
              'USERNAME' => username,
              'PASSWORD' => password,
              'loginBtn' => 'Login' # Found in the HTML form
            }
          })

          unless res
            return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
          end

          # After login, the application should give us a new SID
          cookies = res.get_cookies
          sid = cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
          @last_sid = sid # Update our SID

          if res.headers['Location'].to_s.include?('executive_summary.php') && !sid.blank?
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.to_s}
          end

          {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
        end


        # Attempts to login to Symantec Web Gateway. This is called first.
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          result_opts = { credential: credential }

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

