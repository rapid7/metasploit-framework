require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Jupyter login scanner
      class Jupyter < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 8888
        PRIVATE_TYPES   = [ :password ]

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = '/login' if self.uri.nil?
          self.method = 'POST' if self.method.nil?

          super
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp',
            service_name: ssl ? 'https' : 'http'
          }

          begin
            res = send_request({'method'=> 'GET', 'uri' => uri})
            vars_post = {'password' => credential.private }

            # versions < 4.3.1 do not use this field
            unless (node = res.get_html_document.xpath('//form//input[@name="_xsrf"]')).empty?
              vars_post['_xsrf'] = node.first['value']
            end

            res = send_request({
              'method' => 'POST',
              'uri' => uri,
              'cookie' => res.get_cookies,
              'vars_post' => vars_post
            })

            if res&.code == 302 && res.headers['Location']
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.headers)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end
          rescue ::EOFError, Errno::ETIMEDOUT, Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end
          Result.new(result_opts)
        end
      end
    end
  end
end
