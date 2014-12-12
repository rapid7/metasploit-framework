require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Jenkins login scanner
      class Jenkins < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 8080
        PRIVATE_TYPES   = [ :password ]

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/j_acegi_security_check" if self.uri.nil?
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
            cli = Rex::Proto::Http::Client.new(host, port, {}, ssl, ssl_version, proxies)
            cli.connect
            req = cli.request_cgi({
              'method'=>'POST',
              'uri'=>'/j_acegi_security_check',
              'vars_post'=> {
                'j_username' => credential.public,
                'j_password'=>credential.private
                }
            })
            res = cli.send_recv(req)
            if res && !res.headers['location'].include?('loginError')
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.headers)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end
          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end
          Result.new(result_opts)
        end
      end
    end
  end
end
