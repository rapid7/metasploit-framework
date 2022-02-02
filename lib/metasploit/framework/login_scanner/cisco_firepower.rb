require 'metasploit/framework/login_scanner/http'
require 'digest'

module Metasploit
  module Framework
    module LoginScanner

      class CiscoFirepower < HTTP

        DEFAULT_PORT  = 443
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name

        def check_setup
          res = send_request({
            'method' => 'GET',
            'uri'    => normalize_uri("#{uri}login.cgi")
          })

          if res && res.code == 200 && res.body.include?('/img/favicon.png?v=6.0.1-1213')
            return true
          end

          false
        end

        def do_login(cred)
          console_user = cred.public
          console_pass = cred.private

          res = send_request({
            'method' => 'POST',
            'uri'    => normalize_uri("#{uri}login.cgi"),
            'vars_post' => {
            'username' => console_user,
            'password' => console_pass,
            'target'   => ''
            }
          })

          unless res
            return {status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: 'Connection timed out for login.cig'}
          end

          if res.code == 302 && res.get_cookies.include?('CGISESSID')
            return {status: LOGIN_STATUS::SUCCESSFUL, proof: res.body}
          end

          {status: LOGIN_STATUS::INCORRECT, proof: res.body}
        end

        # Attempts to login to Cisco. This is called first.
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
            result_opts.merge!(do_login(credential))
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

