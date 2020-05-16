
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

        # The default realm is WORKSTATION which tells Windows authentication
        # that it is a Local Account.
        DEFAULT_REALM = 'WORKSTATION'

        # The default port where WinRM listens when SSL is enabled. Note
        # that before v1.1, the default was 443
        DEFAULT_SSL_PORT = 5986

        PRIVATE_TYPES = [ :password ]
        LIKELY_PORTS  = [ 80, 443, 5985, 5986 ]
        REALM_KEY     = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
        # Inherit LIKELY_SERVICE_NAMES, since a scanner will see it as
        # just HTTP.

        validates :method, inclusion: { in: ["POST"] }

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.uri = "/wsman" if self.uri.nil?
          @method = "POST".freeze

          super
        end

        # send an HTTP request that WinRM would consider as valid  (SOAP XML in the message matching the XML schema definition)
        def send_request(opts)
            opts['headers'] ||= { }
            opts['ctype'] = 'application/soap+xml;charset=UTF-8'
            opts['data'] = wsman_identity_request
            opts['headers']['Content-Length'] = opts['data'].length
            super
        end

        # The method *must* be "POST", so don't let the user change it
        # @raise [RuntimeError] Unconditionally
        def method=(_)
          raise RuntimeError, "Method must be POST for WinRM"
        end

        private

        def wsman_identity_request
          %Q{<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>}
        end
      end
    end
  end
end

