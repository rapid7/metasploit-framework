require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # Jenkins login scanner
      class Jenkins < HTTP

        include Msf::Exploit::Remote::HTTP::Jenkins

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 8080
        PRIVATE_TYPES   = [ :password ]

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/" if self.uri.nil?
          self.method = "POST" if self.method.nil?

          if self.uri[0] != '/'
            self.uri = "/#{self.uri}"
          end

          super
        end

        # (see Base#check_setup)
        def check_setup
          login_uri = jenkins_login_uri
          if login_uri.nil?
            error_message = 'Unable to locate the Jenkins login path'
          else
            self.uri = normalize_uri(login_uri)
            error_message = false
          end

          error_message
        end

        def jenkins_login_uri
          res = send_request({ 'uri' => normalize_uri('login') })
          if res&.code == 200 && res&.body =~ Msf::Exploit::Remote::HTTP::Jenkins::LOGIN_PATH_REGEX
            login_path = Regexp.last_match(1)
            ilog("Found jenkins login path: #{login_path}")
            return login_path
          end
          wlog('Failed to identify the login resource.')
          nil
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

          status, proof = jenkins_login(credential.public, credential.private) do |request|
            send_request({
              'method' => method,
              'uri' => uri,
              'vars_post' => request['vars_post']
            })
          end

          result_opts.merge!(status: status, proof: proof)

          Result.new(result_opts)
        end
      end
    end
  end
end
