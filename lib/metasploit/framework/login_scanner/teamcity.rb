require 'metasploit/framework/login_scanner/http'
require 'rex/proto/teamcity/rsa'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with JetBrains TeamCity instances.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class Teamcity < HTTP
        DEFAULT_PORT         = 8111
        LIKELY_PORTS         = [8111]
        LIKELY_SERVICE_NAMES = ['skynetflow'] # Comes from nmap 7.95 on MacOS
        PRIVATE_TYPES        = [:password]
        REALM_KEY            = nil

        LOGIN_PAGE = 'login.html'
        LOGOUT_PAGE = 'ajax.html?logout=1'
        SUBMIT_PAGE = 'loginSubmit.html'

        SUCCESSFUL = ::Metasploit::Model::Login::Status::SUCCESSFUL
        UNABLE_TO_CONNECT = ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        INVALID_PUBLIC_PART = ::Metasploit::Model::Login::Status::INVALID_PUBLIC_PART
        LOCKED_OUT = ::Metasploit::Model::Login::Status::LOCKED_OUT
        INCORRECT = ::Metasploit::Model::Login::Status::INCORRECT

        # Send a GET request to the server and return a response.
        # @param [Hash] opts A hash with options that will take precedence over default values used to make the HTTP request.
        # @return [Hash] A hash with a status and an error or the response from the login page.
        def get_page_data(opts: { timeout: 5 })
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s, LOGIN_PAGE)
          }

          opts.each { |param, value| request_params[param] = value }
          begin
            res = send_request(request_params)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: UNABLE_TO_CONNECT, proof: e }
          end

          return { status: UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if res.nil?
          # Does the service need to be setup & configured with the initial DB migration & admin account?
          return { status: UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}. Does the service need to be configured?" } if res.code != 200

          { status: :success, proof: res }
        end

        # Extract the server's public key from the response.
        # @param [Rex::Proto::Http::Response] response The response to extract the public RSA key from.
        # @return [Hash] A hash with a status and an error or the server's public key.
        def get_public_key(response)
          html_doc = response.get_html_document
          public_key_choices = html_doc.xpath('//input[@id="publicKey"]/@value')
          return { status: UNABLE_TO_CONNECT, proof: 'Could not find the TeamCity public key in the HTML document' } if public_key_choices.empty?

          { status: :success, proof: public_key_choices.first.value }
        end

        # Create a login request body for the provided credentials.
        # @param [String] username The username to create the request body for.
        # @param [String] password The user's password.
        # @param [Object] public_key The public key to use when encrypting the password.
        def create_login_request_body(username, password, public_key)
          vars = {}
          vars['username'] = URI.encode_www_form_component(username)
          vars['remember'] = 'true'
          vars['_remember'] = ''
          vars['submitLogin'] = URI.encode_www_form_component('Log in')
          vars['publicKey'] = public_key
          vars['encryptedPassword'] = Rex::Proto::Teamcity::Rsa.encrypt_data(password, public_key)

          vars.each.map { |key, value| "#{key}=#{value}" }.join('&')
        end

        # Create a login request for the provided credentials.
        # @param [String] username The username to create the login request for.
        # @param [String] password The password to log in with.
        # @param [String] public_key The public key to encrypt the password with.
        # @return [Hash] The login request parameter hash.
        def create_login_request(username, password, public_key)
          {
            'method' => 'POST',
            'uri' => normalize_uri(@uri.to_s, SUBMIT_PAGE),
            'ctype' => 'application/x-www-form-urlencoded',
            'data' => create_login_request_body(username, password, public_key)
          }
        end

        # Try logging in with the provided username, password and public key.
        # @param [String] username The username to send the login request for.
        # @param [String] password The user's password.
        # @param [String] public_key The public key used to encrypt the password.
        # @return [Hash] A hash with the status and an error or the response.
        def try_login(username, password, public_key)
          login_request = create_login_request(username, password, public_key)

          begin
            res = send_request(login_request)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: UNABLE_TO_CONNECT, proof: e }
          end

          return { status: UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if res.nil?
          return { status: UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}" } if res.code != 200

          # Check if the current username is timed out. Sleep if so.
          # TODO: This can be improved. The `try_login` method should not block until it can retry credentials.
          # This responsibility should fall onto the caller, and the caller should keep track of the tried, locked out and untried sets of credentials,
          # and it should be up to the caller and its scheduler algorithm to retry credentials, rather than force this method to block.
          # Currently, those building blocks are not available, so this is the approach I have implemented.
          timeout = res.body.match(/login only in (?<timeout>\d+)s/)&.named_captures&.dig('timeout')&.to_i
          if timeout
            framework_module.print_status "User '#{username}' locked out for #{timeout} seconds. Sleeping, and retrying..."
            sleep(timeout + 1) # + 1 as TeamCity is off-by-one when reporting the lockout timer.
            result = try_login(username, password, public_key)
            return result
          end

          return { status: INCORRECT, proof: res } if res.body.match?('Incorrect username or password')
          return { status: UNABLE_TO_CONNECT, proof: res } if res.body.match?('ajax') # TODO: Get the exact error message here.
          return { status: INVALID_PUBLIC_PART, proof: res } if res.body.match?('publicKeyExpired') # TODO: Invalid public part? Or Incorrect/Unable_to_connect?

          { status: :success, proof: res }
        end

        # Send a logout request for the provided user's headers.
        # This header stores the user's cookie.
        # @return [Hash] A hash with the status and an error or the response.
        def logout_with_headers(headers)
          logout_params = {
            'method' => 'POST',
            'uri' => normalize_uri(@uri.to_s, LOGOUT_PAGE),
            'headers' => headers
          }

          begin
            logout_res = send_request(logout_params)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: UNABLE_TO_CONNECT, proof: e }
          end

          return { status: UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if logout_res.nil?
          # A successful logout request wants to redirect us back to the login page
          return { status: UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{logout_res.code}" } if logout_res.code != 302

          { status: :success, proof: logout_res }
        end

        def attempt_login(credential)
          result_options = {
            credential:   credential,
            host:         @host,
            port:         @port,
            protocol:     'tcp',
            service_name: 'teamcity'
          }

          # Needed to retrieve the public key that will be used to encrypt the user's password.
          page_data = get_page_data
          return Result.new(result_options.merge(page_data)) if page_data[:status] != :success

          public_key_result = get_public_key(page_data[:proof])
          return Result.new(result_options.merge(public_key_result)) if public_key_result[:status] != :success

          login_result = try_login(credential.public, credential.private, public_key_result[:proof])
          return Result.new(result_options.merge(login_result)) if login_result[:status] != :success

          # Ensure we log the user out, so that our logged in session does not appear under the user's profile.
          logout_with_headers(login_result[:proof].headers)

          result_options[:status] = SUCCESSFUL
          Result.new(result_options)
        end
      end
    end
  end
end
