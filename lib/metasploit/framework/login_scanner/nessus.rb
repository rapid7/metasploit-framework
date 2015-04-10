
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class Nessus < HTTP

        DEFAULT_PORT  = 8834
        PRIVATE_TYPES = [ :password ]
        LIKELY_SERVICE_NAMES = [ 'nessus' ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name


        # Checks if the target is a Tenable Nessus server.
        #
        # @return [Boolean] TrueClass if target is Nessus server, otherwise FalseClass
        def check_setup
          login_uri = "/server/properties"
          res = send_request({'uri'=> login_uri})
          if res && res.body.include?('Nessus')
            return true
          end

          false
        end

        # Actually doing the login. Called by #attempt_login
        #
        # @param username [String] The username to try
        # @param password [String] The password to try
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def get_login_state(username, password)
          login_uri = "#{uri}"

          res = send_request({
            'uri' => login_uri,
            'method' => 'POST',
            'vars_post' => {
              'username' => username,
              'password' => password
            }
          })

          unless res
            return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
          end
          if res.code == 200 && res.body =~ /token/
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.body.to_s}
          end

          {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}
        end


        # Attempts to login to Nessus.
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
            result_opts.merge!(get_login_state(credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            # Something went wrong during login. 'e' knows what's up.
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          Result.new(result_opts)
        end

        def set_sane_defaults
          super
          # nessus_rest_login has the same default in TARGETURI, but rspec doesn't check nessus_rest_login
          # so we have to set the default here, too.
          self.uri = '/session'
        end

      end
    end
  end
end

