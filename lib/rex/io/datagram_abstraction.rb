#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'socket'

module Rex
module IO

###
#
# This class provides an abstraction to a datagram based
# connection through the use of a datagram socketpair.
#
###
module DatagramAbstraction

  #
  # Creates a streaming socket pair
  #
  def initialize_abstraction
    self.lsock, self.rsock = Rex::Socket.udp_socket_pair()
  end


  # The left side of the stream (local)
  attr_reader :lsock
  # The right side of the stream (remote)
  attr_reader :rsock

protected
  attr_writer :lsock
  attr_writer :rsock

end

end; end
