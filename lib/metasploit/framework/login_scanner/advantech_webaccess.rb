require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class AdvantechWebAccess < HTTP

        DEFAULT_PORT  = 80
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name

        def check_setup
          uri = normalize_uri("#{uri}broadWeb/bwRoot.asp")

          res = send_request({
            'method' => 'GET',
            'uri'    => uri
          })

          if res && res.body =~ /Welcome to Advantech WebAccess/i
            return true
          end

          false
        end

        def do_login(user, pass)
          uri  = normalize_uri("#{uri}broadweb/user/signin.asp")

          res = send_request({
            'method' => 'POST',
            'uri'    => uri,
            'vars_post' =>
              {
                'page'     => '/',
                'pos'      => '',
                'remMe'    => '',
                'submit1'  => 'Login',
                'username' => user,
                'password' => pass
              }
          })

          unless res
            return {status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: 'Connection timed out for signin.asp'}
          end

          if res.headers['Location'] && res.headers['Location'] == '/broadweb/bwproj.asp'
            return {status: LOGIN_STATUS::SUCCESSFUL, proof: res.body}
          end

          {status: LOGIN_STATUS::INCORRECT, proof: res.body}
        end

        # Attempts to login to Advantech WebAccess.
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          begin
            result_opts.merge!(do_login(credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            # Something went wrong during login. 'e' knows what's up.
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          Result.new(result_opts)
        end

      end
    end
  end
end
