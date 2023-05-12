require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class SoftingSIS < HTTP

        DEFAULT_PORT = 8099
        DEFAULT_SSL_PORT = 443
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS = Metasploit::Model::Login::Status

        # Check if the target is Softing Secure Integration Server
        #
        # @return [Boolean] TrueClass if target is SIS, otherwise FalseClass
        def check_setup
          # we can interact with this endpoint as an unauthenticated user
          uri = normalize_uri("#{uri}/runtime/core/product-version")
          res = send_request({ 'uri' => uri })
          # make sure we get a response, and that the check was successful
          unless res && res.code == 200
            return { status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: res.to_s }
          end

          # convert the response to JSON
          # we expect to see a response like {"version" : "1.22.0.8686"}
          res_json = res.get_json_document
          # if we successfully get the version
          if res_json['version']
            # return true
            return res_json['version']
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
          # attempt to get an authentication token
          auth_token_uri = normalize_uri("#{uri}/runtime/core/user/#{user}/authentication-token")

          # send the request to get an authentication token
          auth_res = send_request({
            'method' => 'GET',
            'uri' => auth_token_uri,
            'cookie' => 'lang=en; user=guest'
          })

          # check if we get a response
          unless auth_res
            return { status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: auth_res.to_s }
          end

          # convert the response to JSON
          auth_json = auth_res.get_json_document
          # if the response code is 404, the user does not exist
          if auth_res.code == 404 && auth_json && auth_json['Message']
            return { status: LOGIN_STATUS::INCORRECT, proof: auth_json['Message'] }
          end

          # if the response code is 403, the user exists but access is denied
          if auth_res.code == 403 && auth_json && auth_json['Message']
            return { status: LOGIN_STATUS::DENIED_ACCESS, proof: auth_json['Message'] }
          end

          # get authentication token
          auth_token = auth_json['authentication-token']
          # check that the token is not blank
          if auth_token.blank?
            framework_module.vprint_error('Received empty authentication token!')
            return { status: LOGIN_STATUS::INCORRECT, proof: auth_res.body.to_s }
          end

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
          if res.code == 200 && res_json && res_json['Message'] == 'Success'
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
