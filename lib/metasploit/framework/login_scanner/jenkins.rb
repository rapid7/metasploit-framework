require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # Jenkins login scanner
      class Jenkins < HTTP
        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_HTTP_NOT_AUTHED_CODES = [403]
        DEFAULT_PORT = 8080
        PRIVATE_TYPES = [:password].freeze
        JENKINS_LOGIN_VALIDATION_URL = 'j_spring_security_check'.freeze

        # Checks the setup for the Jenkins Login scanner.
        # Always returns false, as the underlying client does not support checking the
        # conditions due Jenkins not doing Authentication challenges.
        # This is needed for Pro.
        #
        # @return [Boolean] Always returns false.
        def check_setup
          false
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          super

          self.uri ||= '/'

          unless uri.to_s.start_with?('/')
            self.uri = "/#{uri}"
          end
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          if ssl
            result_opts[:service_name] = 'https'
          else
            result_opts[:service_name] = 'http'
          end

          status, proof = jenkins_login(credential.public, credential.private)

          result_opts.merge!(status: status, proof: proof)

          Result.new(result_opts)
        end

        protected

        # Returns a boolean value indicating whether the request requires authentication or not.
        #
        # @param [Rex::Proto::Http::Response] response The response received from the HTTP endpoint
        # @return [Boolean] True if the request required authentication; otherwise false.
        def authentication_required?(response)
          return false unless response

          self.class::DEFAULT_HTTP_NOT_AUTHED_CODES.include?(response.code)
        end

        private

        # This method takes a username and password and a target URI
        # then attempts to login to Jenkins and will either fail with appropriate errors
        #
        # @param [String] username The username for login credentials
        # @param [String] password The password for login credentials
        # @return [Array] [status, proof] The result of the login attempt
        def jenkins_login(username, password)
          begin
            login_url = jenkins_uri_check(uri, keep_cookies: true)
            res = send_request(
              'method' => 'POST',
              'uri' => login_url,
              'vars_post' => {
                'j_username' => username,
                'j_password' => password,
                'Submit' => 'log in'
              }
            )

            if res && res.headers['Location'] && !res.headers['Location'].include?('loginError')
              status = Metasploit::Model::Login::Status::SUCCESSFUL
              proof = res.headers
            else
              status = Metasploit::Model::Login::Status::INCORRECT
              proof = res
            end
          rescue ::EOFError, Errno::ETIMEDOUT, Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            proof = e
          end

          [status, proof]
        end

        # This method uses the provided URI to determine whether login is possible for Jenkins.
        # Based on the contents of the provided URI, the method looks for the login form and
        # extracts the endpoint used to authenticate against.
        #
        # @param [URI, String] target_uri The targets URI
        # @return [String, nil] URI for successful login
        def jenkins_uri_check(target_uri, keep_cookies: false)
          # if keep_cookies is true we get the first cookie that's needed by newer Jenkins versions
          res = send_request(
            'method' => 'GET',
            'uri' => normalize_uri(target_uri, 'login'),
            'keep_cookies' => keep_cookies
          )

          return normalize_uri(target_uri, JENKINS_LOGIN_VALIDATION_URL) unless valid_response?(res)

          if res&.body =~ /action="(j_([a-z0-9_]+))"/
            login_uri = Regexp.last_match(1)

            normalize_uri(target_uri, login_uri)
          else
            normalize_uri(target_uri, JENKINS_LOGIN_VALIDATION_URL)
          end
        end

        # Determines whether the provided response is considered valid or not.
        #
        # @param [Rex::Proto::Http::Response, nil] response The response received from the HTTP request.
        # @return [Boolean] True if the response if valid; otherwise false.
        def valid_response?(response)
          self.http_success_codes.include?(response&.code)
        end
      end
    end
  end
end
