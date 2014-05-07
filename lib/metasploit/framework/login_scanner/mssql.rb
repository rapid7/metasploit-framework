require 'metasploit/framework/mssql/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/login_scanner/ntlm'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Microsoft SQL Servers.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results
      class MSSQL
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::LoginScanner::NTLM
        include Metasploit::Framework::MSSQL::Client


      end

    end
  end
end