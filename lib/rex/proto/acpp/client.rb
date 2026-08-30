# -*- coding: binary -*-

##
# ACPP protocol support
##

module Rex
module Proto
module ACPP

class Client

  def initialize(sock, opts = {})
    @sock = sock
    @opts = opts
  end

  def authenticate(password = 'public')
    login = Message.new
    login.password = password
    login.type = 20
    @sock.put(login.to_s)
    # TODO: the checksum never validates here
    Message.decode(@sock.get_once(128), false)
  end
end
end
end
end
