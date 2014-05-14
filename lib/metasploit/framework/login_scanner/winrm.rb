
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Windows Remote Management login scanner
      class WinRM < HTTP

        # The default port where WinRM listens. This is what you get on
        # v1.1+ with `winrm quickconfig`. Note that before v1.1, the
        # default was 80
        DEFAULT_PORT = 5985

        # The default port where WinRM listens when SSL is enabled. Note
        # that before v1.1, the default was 443
        DEFAULT_SSL_PORT = 5986

        validates :method, inclusion: { in: ["POST"] }

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/wsman" if self.uri.nil?
          @method = "POST".freeze

          super
        end

        # The method *must* be "POST", so don't let the user change it
        # @raise [RuntimeError]
        def method=(_)
          raise RuntimeError, "Method must be POST for WinRM"
        end

      end
    end
  end
end

