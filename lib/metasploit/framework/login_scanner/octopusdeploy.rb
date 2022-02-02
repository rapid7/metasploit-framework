require 'metasploit/framework/login_scanner/http'
require 'json'

module Metasploit
  module Framework
    module LoginScanner

      # Octopus Deploy login scanner
      class OctopusDeploy < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 80
        PRIVATE_TYPES   = [ :password ]

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          uri = '/api/users/login' if uri.nil?
          method = 'POST' if method.nil?

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
            json_post_data = JSON.pretty_generate({ Username: credential.public, Password: credential.private })
            cli = Rex::Proto::Http::Client.new(host, port, { 'Msf' => framework, 'MsfExploit' => framework_module }, ssl, ssl_version, http_username, http_password)
            configure_http_client(cli)
            cli.connect
            req = cli.request_cgi(
              'method' => 'POST',
              'uri' => uri,
              'ctype' => 'application/json',
              'data' => json_post_data
            )
            res = cli.send_recv(req)
            body = JSON.parse(res.body)
            if res && res.code == 200 && body.key?('IsActive') && body['IsActive']
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
