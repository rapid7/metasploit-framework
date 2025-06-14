require 'metasploit/framework/login_scanner/http'
require 'json'

module Metasploit
  module Framework
    module LoginScanner
      class SyncoveryFileSyncBackup < HTTP

        DEFAULT_PORT = 8999 # HTTP=8999; HTTPS=8943
        PRIVATE_TYPES = [ :password ].freeze
        LOGIN_STATUS = Metasploit::Model::Login::Status # Shorter name

        # Checks if the target is Syncovery File Sync & Backup Software. The login module should call this.
        #
        # @return [Boolean] TrueClass if target is Syncovery, otherwise FalseClass
        def check_setup
          login_uri = normalize_uri("#{uri}/")
          res = send_request({ 'uri' => login_uri })

          if res && res.code == 200 && res.body.include?('Syncovery')
            return true
          end

          false
        end

        # Gets the Syncovery version.
        #
        # @return [String] version if version was found, otherwise FalseClass
        def get_version
          globals = normalize_uri("#{uri}/get_global_variables")
          res = send_request({ 'uri' => globals })
          if res && res.code == 200
            json_res = res.get_json_document
            version = json_res['SyncoveryTitle']&.scan(/Syncovery\s([A-Za-z0-9.]+)/)&.flatten&.first || ''
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
          if username.present?
            # use username:password
            res = send_request({
              'uri' => normalize_uri("#{uri}/post_applogin.php"),
              'vars_get' => {
                'login' => username.to_s,
                'password' => password.to_s
              },
              'method' => 'GET'
            })
            unless res
              return { status: LOGIN_STATUS::UNABLE_TO_CONNECT }
            end

            # After login, the application should give us a new token
            # session_token is actually just base64(MM/dd/yyyy HH:mm:ss) at the time of the login
            json_res = res.get_json_document
            token = json_res['session_token']
            if token.present?
              return { status: LOGIN_STATUS::SUCCESSFUL, proof: token.to_s }
            end

            return { proof: res.to_s }
          else
            # no username => token is used as password
            res = send_request({
              'uri' => normalize_uri("#{uri}/profiles.json"),
              'vars_get' => {
                'recordstartindex' => '0',
                'recordendindex' => '0'
              },
              'method' => 'GET',
              'headers' => {
                'token' => password
              }
            })
            unless res
              return { status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: res.to_s }
            end
            if !res.body.to_s.include? 'Session Expired'
              return { status: LOGIN_STATUS::SUCCESSFUL, proof: res.body.to_s }
            end

            return { proof: res.body.to_s }
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
