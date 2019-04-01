require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class PhpMyAdmin < HTTP

        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS = Metasploit::Model::Login::Status

        def check_setup
          version = "Not Detected"
          res = send_request({ 'uri' => uri })

          if res && res.body.include?('phpMyAdmin')
            if res.body =~ /PMA_VERSION:"(\d+\.\d+\.\d+)"/
              version = Gem::Version.new($1)
            end
            return version.to_s
          end

          false
        end

        def get_session_info
          res = send_request({'uri' => uri})
          no_connect = { status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: 'Cannot retrieve session info' }
          return { status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: 'Unable to access PhpMyAdmin login page' } unless res

          return no_connect if (res.get_cookies.scan(/phpMyAdmin=(\w+);*/).flatten[0].nil? || res.body.scan(/token"\s*value="(.*?)"/).flatten[0].nil? || res.get_cookies.split[-2..-1].nil?)
          session_id = res.get_cookies.scan(/phpMyAdmin=(\w+);*/).flatten[0]
          token = Rex::Text.html_decode(res.body.scan(/token"\s*value="(.*?)"/).flatten[0])
          cookies = res.get_cookies.split[-2..-1].join(' ')
          
          info = [session_id, token, cookies]
          return no_connect if (info.empty? || session_id.empty? || token.empty? || cookies.empty?)

          return info
        end

        def do_login(username, password)
          session_info = get_session_info
          # Failed to retrieve session info
          return session_info if session_info.is_a?(Hash)

          protocol  = ssl ? 'https' : 'http'
          peer      = "#{host}:#{port}"

          res = send_request(
            'uri'     => uri,
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

          if res && res.code == 302 && res.headers['Location'].to_s.include?('index.php')
            return { :status => LOGIN_STATUS::SUCCESSFUL, :proof => res.to_s }
          end

          {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
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
