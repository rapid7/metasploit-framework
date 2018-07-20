require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class PhpMyAdmin < HTTP

        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS = Metasploit::Model::Login::Status

        def check_setup
          login_uri = normalize_uri("#{uri}/index.php")
          res = send_request({ 'uri' => login_uri })
          return res && res.body.include?('phpMyAdmin')
        end

        def get_session_info
          login_uri = normalize_uri("#{uri}/index.php")
          res = send_request({'uri' => login_uri})
          return {status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: 'Unable to access PhpMyAdmin login page'} unless res

          session_id = res.get_cookies.scan(/phpMyAdmin=(\w+);*/).flatten[0]
          token = Rex::Text.html_decode(res.body.scan(/token"\s*value="(.*?)"/).flatten[0])
          
          puts "Token here: #{token}"
          puts "Session ID: #{session_id}"
          info = [session_id, token, res.get_cookies.split[-2..-1].join(' ')]
          return info unless session_id.empty? || token.empty?
        end

        def do_login(username, password)
          session_info = get_session_info

          protocol  = ssl ? 'https' : 'http'
          peer      = "#{host}:#{port}"
          login_uri = normalize_uri("#{uri}")

          res = send_request(
            'uri'     => login_uri,
            'method'  => 'POST',
            'cookie'  => session_info.last,
            'vars_post' => {
              'set_session'   => session_info[0],
              'pma_username'  => username,
              'pma_password'  => password,
              'target'        => 'index.php',
              'server'        => 1,
              'token'         => session_info[1]
            }
          )

          puts res.to_s
          # check for redirect in location header, otherwise, can check for result code with regex
          if res && res.code == 302 && res.headers['Location'].to_s.include?('index.php')
            return { :status => LOGIN_STATUS::SUCCESSFUL, :proof => res.to_s }
          end

          { :proof => res.to_s }
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,   
            status: LOGIN_STATUS::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          result_opts.merge!(do_login(credential.public, credential.private))

          Result.new(result_opts)
        end
      end
    end
  end
end
