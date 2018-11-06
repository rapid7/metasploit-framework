# -*- coding: binary -*-

require 'rex/io/socket_abstraction'

module Rex
module IO

###
#
# This class provides an abstraction to a stream based
# connection through the use of a streaming socketpair.
#
###
module StreamAbstraction
  include Rex::IO::SocketAbstraction

  #
  # This method creates a streaming socket pair and initializes it.
  #
  def initialize_abstraction
    self.lsock, self.rsock = Rex::Socket.tcp_socket_pair()
    self.lsock.extend(Rex::IO::Stream)
    self.lsock.extend(Ext)
    self.rsock.extend(Rex::IO::Stream)

    self.monitor_rsock("StreamMonitorRemote")
  end

end

end; end

