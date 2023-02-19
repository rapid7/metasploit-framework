require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class SoftingSIS < HTTP

        DEFAULT_PORT = 8099
        DEFAULT_SSL_PORT = 443
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS = Metasploit::Model::Login::Status

        # Return the authentication token to calculate the signature
        # the authentication token is 32 hexadecimal characters [0-9][a-f]
        #
        # @return [String] The authentication token for Secure Integration Server (SIS)
        def get_auth_token
          uri = normalize_uri("#{uri}/runtime/core/user/admin/authentication-token")

          res = send_request({
            'method' => 'GET',
            'uri' => uri,
            'cookie' => 'lang=en; user=guest'
          })

          # extract the authetication token from the JSON response
          res_json = res.get_json_document
          res_json['authentication-token']
        end

        # Check if the target is Softing Secure Integration Server
        #
        # @return [Boolean] TrueClass if target is SIS, otherwise FalseClass
        def check_setup
          uri = normalize_uri("#{uri}/js/language.js")
          res = send_request({ 'uri' => uri })

          # "/js/language.js" should contain "Secure Integration Server"
          if res && res.body.include?('Secure Integration Server')
            return true
          end

          false
        end

        # the actual login method, called by #attempt_login
        #
        # @param user [String] The username to try
        # @param pass [String] The password to try
        # @return [Hash]
        #   * status [Metasploit::Model::Login::Status]
        #   * proof [String] the HTTP response body
        def do_login(user, pass)
          # prep the data needed for login
          protocol = ssl ? 'https' : 'http'
          auth_token = get_auth_token
          login_uri = normalize_uri("#{uri}/runtime/core/user/#{user}/authentication")
          # calculate signature to use when logging in
          signature = Digest::MD5.hexdigest(auth_token + pass + auth_token + user + auth_token)
          # GET parameters for login
          vars_get = {
            'Signature' => signature,
            'User' => user
          }

          # do the login
          res = send_request({
            'method' => 'GET',
            'uri' => login_uri,
            'cookie' => 'lang=en; user=guest',
            'headers' => { 'Referer' => "#{protocol}://#{host}:#{port}" },
            'vars_get' => vars_get
          })

          unless res
            return { status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: res.to_s }
          end

          # the response is in JSON format
          res_json = res.get_json_document
          # a successful response will contain {"Message": "Success"}
          if res.code.to_i == 200 && res_json && res_json['Message'] == 'Success'
            return { status: LOGIN_STATUS::SUCCESSFUL, proof: res.body }
          end

          { status: LOGIN_STATUS::INCORRECT, proof: res.body }
        end

        # Attempts to login to Softing Secure Integration Server
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
            result_opts.merge!(do_login(credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            # something went wrong during login
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          Result.new(result_opts)
        end

      end
    end
  end
end
