
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Tomcat Manager login scanner
      class Tomcat < HTTP

        # Inherit LIKELY_PORTS,LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        CAN_GET_SESSION = true
        DEFAULT_PORT    = 8180
        PRIVATE_TYPES   = [ :password ]

        # Checks if the target is a Tomcat Manager instance
        #
        # @return [false] if the target looks like Tomcat Manager
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request({
            'method'   => 'GET',
            'uri'      => uri,
            'username' => Rex::Text.rand_text_alpha(8)
          })

          return 'Unable to connect to the Tomcat Manager page' unless res
          return 'Tomcat Manager does not appear to require authentication (Is this really Tomcat Manager?)' unless res.code == 401 && res.headers['WWW-Authenticate'].to_s.include?('Tomcat')

          report_service(service_opts)

          false
        end

        def service_opts
          build_service_opts('tomcat')
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/manager/html" if self.uri.nil?
          self.method = "GET" if self.method.nil?

          super
        end

      end
    end
  end
end

