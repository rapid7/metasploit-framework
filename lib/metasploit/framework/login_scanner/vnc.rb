require 'metasploit/framework/tcp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner
      # This is the LoginScanner class for dealing with the VNC RFB protocol.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class VNC
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client


      end

    end
  end
end