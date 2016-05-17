# -*- coding: binary -*-

require 'rex/io/socket_abstraction'

module Rex
module IO

###
#
# This class provides an abstraction to a datagram based
# connection through the use of a datagram socketpair.
#
###
module DatagramAbstraction
  include Rex::IO::SocketAbstraction

  #
  # Creates a streaming socket pair
  #
  def initialize_abstraction
    self.lsock, self.rsock = Rex::Socket.udp_socket_pair
  end

end

end; end
