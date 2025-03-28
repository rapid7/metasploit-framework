require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Deciso B.V. OPNSense instances.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class OPNSense < HTTP

        def get_cookie_value(response, wanted_cookie_name)
          response.get_cookies.split('; ').find { |cookie| cookie.start_with?(wanted_cookie_name) }.split('=').last
        end

        # Sends a HTTP request with Rex
        #
        # @param (see Rex::Proto::Http::Request#request_raw)
        # @return [Rex::Proto::Http::Response] The HTTP response
        def send_request(opts, keep_cookies = false)
          res = super(opts)

          if keep_cookies && res
            @php_sessid = get_cookie_value(res, 'PHPSESSID')
            @cookie_test = get_cookie_value(res, 'cookie_test')
          end

          res
        end

        # include Msf::Exploit::Remote::HTTP::OPNSense::Login
        # include Msf::Exploit::Remote::HTTP::HttpClient
        # define_method :send_request_cgi, Msf::Exploit::Remote::HttpClient.instance_method(:send_request_cgi)
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

        def query_magic_value
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s)
          }

          res = send_request(request_params, keep_cookies = true)

          if res.nil?
            return { status: :failure, error: 'Did not receive response to a GET request' }
          end

          if res.code != 200
            return { status: :failure, error: "Unexpected return code from GET request - #{res.code}" }
          end

          if res.body.nil?
            return { status: :failure, error: 'Received an empty body from GET request' }
          end

          # The magic name and value are hidden on the login form, so we extract them using Nokogiri.
          form_inputs = ::Nokogiri::HTML(res.body).search('input')
          magic_field = form_inputs.find { |field| field['type'] == 'hidden' }
          if magic_field.nil?
            return { status: :failure, error: 'Could not find hidden magic field in the login form.' }
          end

          { status: :success, result: { name: magic_field['name'], value: magic_field['value'] } }
        end

        # Each individual login needs their own magic name and value.
        # This magic value comes from the login form received in response to a GET request to the login page
        def try_login(username, password, magic_value)
          request_params =
            {
              'method' => 'POST',
              'uri' => normalize_uri(@uri.to_s),
              'cookie' => "PHPSESSID=#{@php_sessid}; cookie_test=#{@cookie_test}",
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
          magic_value = query_magic_value

          if magic_value[:status] != :success
            result_options.merge!(status: ::Metasploit::Model::Login::Status::UNTRIED, proof: magic_value[:error])
            return Result.new(result_options)
          end

          login_result = try_login(credential.public, credential.private, magic_value[:result])

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
