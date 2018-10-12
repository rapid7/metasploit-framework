require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class OutlookWebAccessEWS < HTTP
        DEFAULT_PORT    = 443
        PRIVATE_TYPES   = [ :password ]
        CAN_GET_SESSION = false

        def attempt_login(credential)
          result_opts = {
            credential: credential
          }

          cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => framework_module}, ssl, ssl_version, proxies, http_username, http_password)
          configure_http_client(cli)
          cli.connect

          res = nil
          begin
            req = cli.request_raw({
              'uri'      => uri,
              'method'   => 'GET',
              'username' => credential.public,
              'password' => credential.private
            })

            res = cli.send_recv(req)

          rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
            return Result.new(result_opts)
          end

          if res && res.code != 401 && res.code != 404
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
