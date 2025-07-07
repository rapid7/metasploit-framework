require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Deciso B.V. OPNSense instances.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class OPNSense < HTTP

        # Retrieve the wanted cookie value by name from the HTTP response.
        #
        # @param [Rex::Proto::Http::Response] response The response from which to extract cookie values
        # @param [String] wanted_cookie_name The cookie name for which to get the value
        def get_cookie_value(response, wanted_cookie_name)
          response.get_cookies.split('; ').find { |cookie| cookie.start_with?(wanted_cookie_name) }.split('=').last
        end

        # Checks if the target is OPNSense. The login module should call this.
        #
        # @return [Boolean, String] FalseClass if target is OPNSense, otherwise String
        def check_setup
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s)
          }
          res = send_request(request_params)

          if res && res.code == 200 && res.body&.include?('Login | OPNsense')
            return false
          end

          "Unable to locate \"Login | OPNsense\" in body. (Is this really OPNSense?)"
        end

        # Query the magic value and cookies from the OPNSense login page.
        #
        # @return [Hash<Symbol, Object>] A hash of the status and error or result.
        def query_magic_value_and_cookies
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s)
          }

          res = send_request(request_params)

          if res.nil?
            return { status: :failure, error: 'Did not receive response to a GET request' }
          end

          if res.code != 200
            return { status: :failure, error: "Unexpected return code from GET request - #{res.code}" }
          end

          if res.body.nil?
            return { status: :failure, error: 'Received an empty body from GET request' }
          end

          # The magic name and value are hidden on the login form, so we extract them using get_html_document
          form_input = res.get_html_document&.at('input')

          if form_input.nil? || form_input['type'] != 'hidden'
            return { status: :failure, error: 'Could not find hidden magic field in the login form.' }
          end

          magic_value = { name: form_input['name'], value: form_input['value'] }
          cookies = "PHPSESSID=#{get_cookie_value(res, 'PHPSESSID')}; cookie_test=#{get_cookie_value(res, 'cookie_test')}"
          { status: :success, result: { magic_value: magic_value, cookies: cookies } }
        end

        # Each individual login needs their own magic name and value.
        # This magic value comes from the login form received in response to a GET request to the login page.
        # Each login attempt also requires specific cookies to be set, otherwise an error is returned.
        #
        # @param username Username
        # @param password Password
        # @param magic_value A hash containing the magic_value name and value
        # @param cookies A cookie string
        def try_login(username, password, magic_value, cookies)
          request_params =
            {
              'method' => 'POST',
              'uri' => normalize_uri(@uri.to_s),
              'cookie' => cookies,
              'vars_post' => {
                magic_value[:name] => magic_value[:value],
                'usernamefld' => username,
                'passwordfld' => password,
                'login' => '1'
              }
            }

          { status: :success, result: send_request(request_params) }
        end

        def attempt_login(credential)
          result_options = {
            credential:   credential,
            host:         @host,
            port:         @port,
            protocol:     'tcp',
            service_name: 'opnsense'
          }

          # Each login needs its own magic name and value
          magic_value_and_cookies = query_magic_value_and_cookies

          if magic_value_and_cookies[:status] != :success
            result_options.merge!(status: ::Metasploit::Model::Login::Status::UNTRIED, proof: magic_value_and_cookies[:error])
            return Result.new(result_options)
          end

          login_result = try_login(credential.public, credential.private, magic_value_and_cookies[:result][:magic_value], magic_value_and_cookies[:result][:cookies])

          if login_result[:result].nil?
            result_options.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to OPNSense')
            return Result.new(result_options)
          end

          # 200 is incorrect result
          if login_result[:result].code == 200 || login_result[:result].body.include?('Username or Password incorrect')
            result_options.merge!(status: ::Metasploit::Model::Login::Status::INCORRECT, proof: 'Username or Password incorrect')
            return Result.new(result_options)
          end

          login_status = login_result[:result].code == 302 ? ::Metasploit::Model::Login::Status::SUCCESSFUL : ::Metasploit::Model::Login::Status::INCORRECT
          result_options.merge!(status: login_status, proof: login_result[:result])
          Result.new(result_options)

        rescue ::Rex::ConnectionError => _e
          result_options.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to OPNSense')
          return Result.new(result_options)
        end
      end
    end
  end
end
