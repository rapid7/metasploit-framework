# -*- coding: binary -*-
require 'rex/socket'
require 'rex/socket/tcp'
require 'rex/io/stream_server'

###
#
# This class provides methods for interacting with a TCP server.  It
# implements the Rex::IO::StreamServer interface.
#
###
module  Rex::Socket::TcpServer

  include Rex::Socket
  include Rex::IO::StreamServer

  ##
  #
  # Factory
  #
  ##

  #
  # Creates the server using the supplied hash.
  #
  def self.create(hash = {})
    hash['Proto'] = 'tcp'
    hash['Server'] = true
    self.create_param(Rex::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base class' creation method that automatically sets
  # the parameter's protocol to TCP and sets the server flag to true.
  #
  def self.create_param(param)
    param.proto  = 'tcp'
    param.server = true
    Rex::Socket.create_param(param)
  end

  #
  # Accepts a child connection.
  #
  def accept(opts = {})
    t = super()

    # jRuby compatibility
    if t.respond_to?('[]')
      t = t[0]
    end

    if (t)
      t.extend(Rex::Socket::Tcp)
      t.context = self.context

      pn = t.getpeername

      t.peerhost = pn[1]
      t.peerport = pn[2]
    end

    t
  end

end

