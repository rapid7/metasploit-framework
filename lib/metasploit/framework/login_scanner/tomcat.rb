
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Tomcat Manager login scanner
      class Tomcat < HTTP

        DEFAULT_PORT = 8180

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

