
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

