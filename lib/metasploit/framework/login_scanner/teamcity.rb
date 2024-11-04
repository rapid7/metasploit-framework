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

        class TeamCityError < StandardError; end
        class StackLevelTooDeepError < TeamCityError; end
        class NoPublicKeyError < TeamCityError; end
        class PublicKeyExpiredError < TeamCityError; end
        class DecryptionException < TeamCityError; end
        class ServerNeedsSetupError < TeamCityError; end

        # Extract the server's public key from the server.
        # @return [Hash] A hash with a status and an error or the server's public key.
        def get_public_key
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s, LOGIN_PAGE)
          }

          begin
            res = send_request(request_params)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if res.nil?

          raise ServerNeedsSetupError, 'The server has not performed the initial setup' if res.code == 503

          html_doc = res.get_html_document
          public_key = html_doc.xpath('//input[@id="publicKey"]/@value').text
          raise NoPublicKeyError, 'Could not find the TeamCity public key in the HTML document' if public_key.empty?

          { status: :success, proof: public_key }
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
            'vars_post' => {
              username: username,
              remember: true,
              _remember: '',
              submitLogin: 'Log in',
              publicKey: public_key,
              encryptedPassword: Rex::Proto::Teamcity::Rsa.encrypt_data(password, public_key)
            }
          }
        end

        # Try logging in with the provided username, password and public key.
        # @param [String] username The username to send the login request for.
        # @param [String] password The user's password.
        # @param [String] public_key The public key used to encrypt the password.
        # @return [Hash] A hash with the status and an error or the response.
        def try_login(username, password, public_key, retry_counter = 0)
          raise StackLevelTooDeepError, 'try_login stack level too deep!' if retry_counter >= 2

          login_request = create_login_request(username, password, public_key)

          begin
            res = send_request(login_request)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if res.nil?
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}" } if res.code != 200

          # Check if the current username is timed out. Sleep if so.
          # TODO: This can be improved. The `try_login` method should not block until it can retry credentials.
          # This responsibility should fall onto the caller, and the caller should keep track of the tried, locked out and untried sets of credentials,
          # and it should be up to the caller and its scheduler algorithm to retry credentials, rather than force this method to block.
          # Currently, those building blocks are not available, so this is the approach I have implemented.
          timeout = res.body.match(/login only in (?<timeout>\d+)s/)&.named_captures&.dig('timeout')&.to_i
          if timeout
            framework_module.print_status "User '#{username}' locked out for #{timeout} seconds. Sleeping, and retrying..."
            sleep(timeout + 1) # + 1 as TeamCity is off-by-one when reporting the lockout timer.
            result = try_login(username, password, public_key, retry_counter + 1)
            return result
          end

          return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res } if res.body.match?('Incorrect username or password')

          raise DecryptionException, 'The server failed to decrypt the encrypted password' if res.body.match?('DecryptionFailedException')
          raise PublicKeyExpiredError, 'The server public key has expired' if res.body.match?('publicKeyExpired')

          { status: :success, proof: res }
        end

        # Send a logout request for the provided user's headers.
        # This header stores the user's cookie.
        def logout_with_headers(headers)
          logout_params = {
            'method' => 'POST',
            'uri' => normalize_uri(@uri.to_s, LOGOUT_PAGE),
            'headers' => headers
          }

          send_request(logout_params)
        end

        def attempt_login(credential)
          result_options = {
            credential:   credential,
            host:         @host,
            port:         @port,
            protocol:     'tcp',
            service_name: 'teamcity'
          }

          if @public_key.nil?
            public_key_result = get_public_key
            return Result.new(result_options.merge(public_key_result)) if public_key_result[:status] != :success

            @public_key = public_key_result[:proof]
          end

          login_result = try_login(credential.public, credential.private, @public_key)
          return Result.new(result_options.merge(login_result)) if login_result[:status] != :success

          # Ensure we log the user out, so that our logged in session does not appear under the user's profile.
          logout_with_headers(login_result[:proof].headers)

          result_options[:status] = ::Metasploit::Model::Login::Status::SUCCESSFUL
          Result.new(result_options)
        end

        private

        attr_accessor :public_key

      end
    end
  end
end
