require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Netgate pfSense instances.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class PfSense < HTTP
        LOGIN_ENDPOINT = 'index.php'

        # Checks if the target is pfSense. The login module should call this.
        #
        # @return [Boolean, String] FalseClass if target is pfSense, otherwise String
        def check_setup
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s, LOGIN_ENDPOINT)
          }
          res = send_request(request_params)

          if res&.code == 200 && res.body&.include?('Login to pfSense')
            return false
          end

          "Unable to locate \"Login to pfSense\" in body. (Is this really pfSense?)"
        end

        def query_csrf_magic
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s, LOGIN_ENDPOINT)
          }

          res = send_request(request_params)

          if res.nil?
            return { status: :failure, error: 'Did not receive response to a GET request' }
          end

          if res.code != 200
            return { status: :failure, error: "Unexpected return code from GET request - #{res.code}" }
          end

          # CSRF Magic Token and Magic Value are inlined as JavaScript in a <script> tag.
          # It can also be extracted from the Nokogiri::HTML(res.body).search('form') form.
          csrf_magic_token, csrf_magic_name = res.body.match(/var csrfMagicToken = "(?<magic_token>.*)";var csrfMagicName = "(?<magic_name>.*)";/).captures
          if csrf_magic_token.nil? || csrf_magic_name.nil?
            return { status: :failure, error: "Could not find magic CSRF values. csrf_magic_token: '#{csrf_magic_token}', csrf_magic_name: '#{csrf_magic_name}'" }
          end

          { status: :success, result: { csrf_magic_token: csrf_magic_token, csrf_magic_name: csrf_magic_name } }
        end

        # Each individual login needs their own CSRF magic header.
        # This header comes from a GET request to the index.php page
        def try_login(username, password, csrf_magic)
          request_params =
            {
              'method' => 'POST',
              'uri' => normalize_uri(@uri.to_s, LOGIN_ENDPOINT),
              'keep_cookies' => true,
              'vars_post' => {
                'usernamefld' => username,
                'passwordfld' => password,
                csrf_magic[:csrf_magic_name] => csrf_magic[:csrf_magic_token],
                'login' => ::URI.encode_www_form_component('Sign In')
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
            service_name: 'pfsense'
          }

          # Each login needs its own csrf magic tokens
          csrf_magic = query_csrf_magic

          if csrf_magic[:status] != :success
            result_options.merge!(status: ::Metasploit::Model::Login::Status::UNTRIED, proof: csrf_magic[:error])
            return Result.new(result_options)
          end

          login_result = try_login(credential.public, credential.private, csrf_magic[:result])

          if login_result[:result].nil?
            result_options.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to pfSense')
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
          result_options.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to pfSense')
          return Result.new(result_options)
        end
      end
    end
  end
end
