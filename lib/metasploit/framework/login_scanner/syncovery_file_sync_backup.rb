require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class SyncoveryFileSyncBackup < HTTP

        DEFAULT_PORT  = 8999 # HTTP=8999; HTTPS=8943
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name

        # Checks if the target is Syncovery File Sync & Backup Software. The login module should call this.
        #
        # @return [Boolean] TrueClass if target is Syncovery, otherwise FalseClass
        def check_setup
          login_uri = normalize_uri("#{uri}/")
          res = send_request({'uri'=> login_uri})

          if res && res.code == 200 && (res.body.include?('You can now log in to Syncovery on your machine') || res.body.include?('Syncovery'))
            return true
          end

          false
        end

        # Checks if Syncovery Linux is used.
        #
        # @return [Boolean] true if Linux was found, otherwise FalseClass
        def is_Linux?
          globals = normalize_uri("#{uri}/get_global_variables")
          res = send_request({'uri'=> globals})

          if res && res.code == 200
            if res.body.scan(/"isSyncoveryLinux":"true"/).flatten[0] || res.body.scan(/"isSyncoveryWindows":"false"/).flatten[0]
              return true
            end

            false
          end

          false
        end

        # Gets the Syncovery version.
        #
        # @return [String] version if version was found, otherwise FalseClass
        def get_version
          globals = normalize_uri("#{uri}/get_global_variables")
          res = send_request({'uri'=> globals})

          if res && res.code == 200
            version = res.body.scan(/"SyncoveryTitle":"Syncovery\s([A-Za-z0-9\.]+)/).flatten[0] || ''
            return version
          end

          false
        end

        # Actually doing the login. Called by #attempt_login
        #
        # @param username [String] The username to try
        # @param password [String] The password or token to try
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body or the session token
        def get_login_state(username, password)
          # Prep the data needed for login
          protocol  = ssl ? 'https' : 'http'
          peer      = "#{host}:#{port}"

          if username.empty?
            # no username => token is used as password
            login_uri = normalize_uri("#{uri}/profiles.json?recordstartindex=0&recordendindex=0")
            res = send_request({
              'uri' => login_uri,
              'method' => 'GET',
              'headers' => {
                'token' => password,
              }
            })
            unless res
              return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
            end
            if !(res.body.to_s).include? "Session Expired"
              return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.body.to_s}
            end
            return {:status => LOGIN_STATUS::INCORRECT, :proof => res.body.to_s}
          else
            # use username:password
            login_uri = normalize_uri("#{uri}/post_applogin.php?login=#{username}&password=#{password}")

            res = send_request({
              'uri' => login_uri,
              'method' => 'GET'
            })
            unless res
              return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
            end
            # After login, the application should give us a new token
            # session_token is actually just base64(MM/dd/yyyy HH:mm:ss) at the time of the login
            token = res.body.scan(/"session_token":"((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)"/).flatten[0] || ''
            if !token.blank?
              return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => token.to_s}
            end
            return {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
          end
        end


        # Attempts to login to Syncovery File Sync & Backup Software. This is called first.
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
