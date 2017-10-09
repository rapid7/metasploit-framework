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

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = '/users/sign_in' if uri.nil?
          self.method = 'POST' if method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp',
            service_name: ssl ? 'https' : 'http'
          }
          begin
            cli = Rex::Proto::Http::Client.new(host,
                                               port,
                                               {
                                                 'Msf' => framework,
                                                 'MsfExploit' => framework_module
                                               },
                                               ssl,
                                               ssl_version,
                                               proxies,
                                               http_username,
                                               http_password)
            configure_http_client(cli)
            cli.connect

            # Get a valid session cookie and authenticity_token for the next step
            req = cli.request_cgi(
              'method' => 'GET',
              'cookie' => 'request_method=GET',
              'uri'    => uri
            )

            res = cli.send_recv(req)

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
            # Try it, if the old one was not successfull
            auth_token = res.body.scan(/<input type="hidden" name="authenticity_token" value="(.*?)"/).flatten[0] unless auth_token

            fail RuntimeError, 'Unable to get Session Cookie' unless local_session_cookie
            fail RuntimeError, 'Unable to get Authentication Token' unless auth_token

            # Perform the actual login
            req = cli.request_cgi(
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

            res = cli.send_recv(req)
            if res && res.code == 302
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.headers)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end
          rescue ::EOFError, Errno::ETIMEDOUT ,Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          ensure
            cli.close
          end
          Result.new(result_opts)
        end
      end
    end
  end
end
