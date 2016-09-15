require 'metasploit/framework/login_scanner/http'
require 'json'

module Metasploit
  module Framework
    module LoginScanner

      # Buffalo Linkstation NAS login scanner
      class Buffalo < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 80
        PRIVATE_TYPES   = [ :password ]

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/dynamic.pl" if self.uri.nil?
          self.method = "POST" if self.method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
              credential: credential,
              host: host,
              port: port,
              protocol: 'tcp'
          }
          if ssl
            result_opts[:service_name] = 'https'
          else
            result_opts[:service_name] = 'http'
          end
          begin
            cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => framework_module}, ssl, ssl_version, http_username, http_password)
            configure_http_client(cli)
            cli.connect
            req = cli.request_cgi({
              'method'=>'POST',
              'uri'=>'/dynamic.pl',
              'vars_post'=> {
                'bufaction'=>'verifyLogin',
                'user' => credential.public,
                'password'=>credential.private
                }
            })
            res = cli.send_recv(req)
            body = JSON.parse(res.body)
            if res && body.has_key?('success') && body['success']
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.body)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end
          rescue ::JSON::ParserError
            result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res.body)
          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
          end
          Result.new(result_opts)
        end
      end
    end
  end
end
