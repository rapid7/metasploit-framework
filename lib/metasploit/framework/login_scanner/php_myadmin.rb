require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class PhpMyAdmin < HTTP

        DEFAULT_PORT = 80
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS = Metasploit::Model::Login::Status # shorter name
        
        
        # Sends a HTTP request with Rex
        #
        # @param (see Rex::Proto::Http::Resquest#request_raw)
        # @return [Rex::Proto::Http::Response] The HTTP response
        def send_request(opts)
          cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => self}, ssl, ssl_version, proxies)
          configure_http_client(cli)
          cli.connect
          req = cli.request_raw(opts)
          res = cli.send_recv(req)

          # Save the session ID cookie
          if res && res.get_cookies =~ /(_\w+_session)=([^;$]+)/i
            self.session_name = $1
            self.session_id = $2
          end

          res
        end

        def check_setup
          res = send_request(
            {
              'uri'  => "#{uri}"
            }
          )
          if res && res.body && res.body.include?('phpMyAdmin')
            return true
          end

          return false
        end

        def is_logged_in(url, cookies)
          res = send_request({
            'method' => 'GET',
            'uri'    => normalize_uri("#{url}"),
            'cookie' => cookies
          })    
          return !(res.body.include? '<div class="error">')
        end

        def get_important_cookies_and_token
          cookies = ''

          res = send_request({
            'method' => 'GET',
            'uri'    => normalize_uri("#{uri}")
          })

          return nil if (res.nil? || res.get_cookies.empty?)

          # Get the cookies
          # seuls les derniers comptent (d'ou le m[-1])
          m = res.get_cookies.match(/(phpMyAdmin=[a-z0-9]+;)/)
          pma_session = (m.nil?) ? nil : m[-1]
          m = res.get_cookies.match(/(pma_lang=[a-z]+;)/)
          pma_lang = (m.nil?) ? nil : m[-1]
          m = res.get_cookies.match(/(pma_collation_connection=[a-z0-9_]+;)/)
          pma_collation_connection = (m.nil?) ? nil : m[-1]
          m = res.get_cookies.match(/(pma_mcrypt_iv=[a-zA-Z0-9%]+;)/)
          pma_mcrypt_iv = (m.nil?) ? nil : m[-1]
          # check if everythong is okay
          if pma_session.nil? or pma_lang.nil? or pma_collation_connection.nil? or pma_mcrypt_iv.nil?
            vprint_error("#{peer} - Unable to obtain all cookies, cannot continue")
            return :abort
          else
            vprint_status("#{peer} - Using session ID: #{pma_session}")
          end
          cookies = pma_session + pma_lang + pma_collation_connection + pma_mcrypt_iv

          # Get token
          doc = REXML::Document.new res.body
          if !doc
            fail_with(Failure::UnexpectedReply, 'Error getting token')
          end
          token = REXML::XPath.first(doc, "//input[@name='token']/@value").value

          return pma_lang, pma_collation_connection, cookies, token
        end

        def do_login(username, password)
          # Get a new session with IDs and other cookies. That way if we get a successful login,
          # we won't get a false positive due to reusing the same cookies.

          pma_lang, pma_collation_connection, cookies, token = get_important_cookies_and_token

          res = send_request({
            'method'    => 'POST',
            'uri'       => "#{uri}",
            'cookie'    => cookies, 
            'vars_post' => {
              'token'                => token,
              'pma_username'         => username,
              'pma_password'         => password,
              'server'               => '1',
              'lang'                 => pma_lang,
              'collation_connection' => pma_collation_connection,
            }
          })

          unless res
            return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
          end

          # On complete nos cookies
          m = res.get_cookies.match(/(pmaUser-1=[a-zA-Z0-9%]+;)/)
          pmaUser_1 = (m.nil?) ? nil : m[-1]
          m = res.get_cookies.match(/(pmaPass-1=[a-zA-Z0-9%]+;)/)
          pmaPass_1 = (m.nil?) ? nil : m[-1]
          if pmaUser_1 && pmaPass_1
            cookies = pmaUser_1+ pmaPass_1
          end
          location = res.headers['Location']
          if is_logged_in(location, cookies)
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => pmaPass_1}
          end

          return {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
        end


        # Attemps to login to the server.
        #
        # @param [Metasploit::Framework::Credential] credential The credential information.
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          # Default Result
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          # Merge login result
          begin
            result_opts.merge!(do_login(credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            # Something went wrong during login. 'e' knows what's up.
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          # Return the Result object
          return Result.new(result_opts)
        end

      end
    end
  end
end
