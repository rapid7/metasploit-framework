require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # Jenkins login scanner
      class Jenkins < HTTP
        include Msf::Exploit::Remote::HTTP::Jenkins

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION             = true
        DEFAULT_AUTHORIZATION_CODES = [403]
        DEFAULT_PORT                = 8080
        PRIVATE_TYPES               = [:password]

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/j_acegi_security_check" if self.uri.nil?
          self.method = "POST" if self.method.nil?

          if self.uri[0] != '/'
            self.uri = "/#{self.uri}"
          end

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

        protected

        # Returns a boolean value indicating whether the request requires authentication or not.
        #
        # @param [Rex::Proto::Http::Response] response The response received from the HTTP endpoint
        # @return [Boolean] True if the request required authentication; otherwise false.
        def no_authentication_required?(response)
          return true unless response

          !self.class::DEFAULT_AUTHORIZATION_CODES.include?(response.code)
        end
      end
    end
  end
end
