
require 'metasploit/framework/login_scanner/http'

##
#
# This mixin is for HP System Management login tested on v6.3.1.24 upto v7.2.1.3 and 7.4
#
##

module Metasploit
  module Framework
    module LoginScanner

      class Smh < HTTP

        DEFAULT_PORT  = 4848
        PRIVATE_TYPES = [ :password ]

        #
        # Decides which login routine and returns the results
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result]
        #
        def attempt_login(credential)
          result_opts = {
            credential: credential
          }

          req_opts = {
            'method' => 'POST',
            'uri'    => '/proxy/ssllogin',
            'vars_post' => {
              'redirecturl'         => '',
              'redirectquerystring' => '',
              'user'                => credential.public,
              'password'            => credential.private
            }
          }

          res = nil

          begin
            cli = Rex::Proto::Http::Client.new(host, port, {}, ssl, ssl_version)
            cli.connect
            req = cli.request_cgi(req_opts)
            res = cli.send_recv(req)

          rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, ::EOFError, ::Timeout::Error
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
          end

          if res && res.headers['CpqElm-Login'].to_s =~ /success/
            result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL)
          else
            result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT)
          end

          Result.new(result_opts)
        end

      end
    end
  end
end
