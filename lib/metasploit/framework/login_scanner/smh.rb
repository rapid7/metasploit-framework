
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # HP System Management login scanner tested on v6.3.1.24 upto v7.2.1.3 and 7.4
      class Smh < HTTP

        DEFAULT_PORT  = 4848
        PRIVATE_TYPES = [ :password ]
        CAN_GET_SESSION = true


        # (see Base#attempt_login)
        def attempt_login(credential)
          result_opts = {
            credential: credential
          }

          req_opts = {
            'method' => 'POST',
            'uri'    => uri,
            'vars_post' => {
              'redirecturl'         => '',
              'redirectquerystring' => '',
              'user'                => credential.public,
              'password'            => credential.private
            }
          }

          res = nil

          begin
            cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => framework_module}, ssl, ssl_version, proxies, http_username, http_password)
            configure_http_client(cli)
            cli.connect
            req = cli.request_cgi(req_opts)
            res = cli.send_recv(req)

          rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, ::EOFError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
            return Result.new(result_opts)
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
