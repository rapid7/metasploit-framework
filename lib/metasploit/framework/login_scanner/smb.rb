require 'rex/proto/smb'
require 'metasploit/framework/login_scanner/base'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with the Server Messaging
      # Block protocol.
      class SMB
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::Tcp
        include Metasploit::Framework::LoginScanner::RexSocket

        # (see Base#attempt_login)
        def attempt_login(credential)
          socket = connect

          client = Rex::Proto::SMB::Client.new(socket)
          client.negotiate

          begin
            ok = client.session_setup(credential.public, credential.private, credential.realm||".")
            status = ok ? :success : :failed
          rescue Rex::Proto::SMB::Exceptions::Error
            p $!
          end

          Result.new(credential: credential, status: status)
        ensure
          socket.close unless socket.closed?
        end

        def set_sane_defaults
          self.connection_timeout = 10
          self.max_send_size = 0
          self.stop_on_success = false
          self.send_delay = 0
        end

      end
    end
  end
end

