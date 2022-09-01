# -*- coding: binary -*-

require 'rex/io/datagram_abstraction'
require 'rex/post/meterpreter/channels/socket_abstraction'

module Rex
module Post
module Meterpreter

###
#
# Stream
# ------
#
# This class represents a channel that is streaming.  This means
# that sequential data is flowing in either one or both directions.
#
###
class Datagram < Rex::Post::Meterpreter::Channel

  include Rex::Post::Meterpreter::SocketAbstraction
  include Rex::IO::DatagramAbstraction

  class << self
    def cls
      return CHANNEL_CLASS_DATAGRAM
    end
  end

  module SocketInterface
    include Rex::Post::Meterpreter::SocketAbstraction::SocketInterface
    def type?
      'udp'
    end

    def recvfrom_nonblock(length, flags = 0)
      data = super(length, flags)[0]
      sockaddr = super(length, flags)[0]
      [data, sockaddr]
    end

    #
    # This should work just like a UDPSocket.send method
    #
    # send(mesg, flags, host, port) => numbytes_sent click to toggle source
    # send(mesg, flags, sockaddr_to) => numbytes_sent
    # send(mesg, flags) => numbytes_sent
    #
    def send(buf, flags, a = nil, b = nil)
      channel.send(buf, flags, a, b)
    end
  end

  def dio_write_handler(packet, data)
    @recvd ||= []
    @recvd << [packet, data]
    peerhost = packet.get_tlv_value(
      Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_PEER_HOST
    )
    peerport = packet.get_tlv_value(
      Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_PEER_PORT
    )

    if peerhost && peerport
      # A datagram can be maximum 65507 bytes, truncate longer messages
      rsock.syswrite(data[0..65506])

      # We write the data and sockaddr data to the local socket, the pop it
      # back in recvfrom_nonblock.
      rsock.syswrite(Rex::Socket.to_sockaddr(peerhost, peerport))
      return true
    else
      return false
    end
  end

end

end; end; end
