require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Western Digital MyBook Live login scanner
      class MyBookLive < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 80
        PRIVATE_TYPES   = [ :password ]

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = '/UI/login' if self.uri.nil?
          self.method = 'POST' if self.method.nil?

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
            cred = Rex::Text.uri_encode(credential.private)
            body = "data%5BLogin%5D%5Bowner_name%5D=admin&data%5BLogin%5D%5Bowner_passwd%5D=#{cred}"
            cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => framework_module}, ssl, ssl_version, http_username, http_password)
            configure_http_client(cli)
            cli.connect
            req = cli.request_cgi(
              'method' => method,
              'uri' => uri,
              'data' => body
            )
            res = cli.send_recv(req)
            if res && res.code == 302 && res.headers['location'] && res.headers['location'].include?('UI')
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.headers)
            elsif res.nil?
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: 'No response')
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res.headers)
            end
          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
          end
          Result.new(result_opts)
        end
      end
    end
  end
end
