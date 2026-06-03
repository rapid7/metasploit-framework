require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # GitLab login scanner
      class GitLab < HTTP
        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = false
        DEFAULT_PORT    = 80
        PRIVATE_TYPES   = [ :password ]

        # Checks if the target is a GitLab instance
        #
        # @return [false] if the target looks like GitLab
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request(
            'method' => 'GET',
            'cookie' => 'request_method=GET',
            'uri'    => uri
          )

          return 'Unable to connect to the GitLab login page' unless res
          return 'Unable to locate GitLab login page (Is this really GitLab?)' unless res.code == 200 && (res.body.include?('user[email]') || res.body.include?('user[login]'))

          if res.body.include?('user[email]')
            framework_module&.vprint_status('GitLab v5 login page')
          elsif res.body.include?('user[login]')
            framework_module&.vprint_status('GitLab v7 login page')
          end

          report_service(service_opts)

          false
        end

        def service_opts
          build_service_opts('gitlab')
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = '/users/sign_in' if uri.nil?
          self.method = 'POST' if method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            **service_as_result(service_opts)
          }
          begin
            # Get a valid session cookie and authenticity_token for the next step
            res = send_request(
              'method' => 'GET',
              'cookie' => 'request_method=GET',
              'uri'    => uri
            )

            if res.body.include? 'user[email]'
              user_field = 'user[email]'
            elsif res.body.include? 'user[login]'
              user_field = 'user[login]'
            else
              fail RuntimeError, 'Not a valid GitLab login page'
            end

            local_session_cookie = res.get_cookies.scan(/(_gitlab_session=[A-Za-z0-9%-]+)/).flatten[0]
            auth_token = res.body.scan(/<input name="authenticity_token" type="hidden" value="(.*?)"/).flatten[0]

            # New versions of GitLab use an alternative scheme
            # Try it, if the old one was not successful
            auth_token = res.body.scan(/<input type="hidden" name="authenticity_token" value="(.*?)"/).flatten[0] unless auth_token

            fail RuntimeError, 'Unable to get Session Cookie' unless local_session_cookie
            fail RuntimeError, 'Unable to get Authentication Token' unless auth_token

            # Perform the actual login
            res = send_request(
                                    'method' => 'POST',
                                    'cookie' => local_session_cookie,
                                    'uri'    => uri,
                                    'vars_post' =>
                                      {
                                        'utf8' => "\xE2\x9C\x93",
                                        'authenticity_token' => auth_token,
                                        "#{user_field}" => credential.public,
                                        'user[password]' => credential.private,
                                        'user[remember_me]' => 0
                                      }
            )

            if res && res.code == 302
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.headers)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end
          rescue ::EOFError, Errno::ETIMEDOUT ,Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end
          Result.new(result_opts)
        end

        def service_opts
          build_service_opts('gitlab')
        end
      end
    end
  end
end
