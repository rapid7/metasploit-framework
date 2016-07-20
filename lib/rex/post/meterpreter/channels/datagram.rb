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

    def recvfrom_nonblock(length,flags = nil)
      return [super(length, flags)[0], super(length, flags)[0]]
    end

    def send(buf, flags, saddr)
      channel.send(buf, flags, saddr)
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
      # Maxlen here is 65507, to ensure we dont overflow, we need to write twice
      # If the other side has a full 64k, handle by splitting up the datagram and
      # writing multiple times along with the sockaddr. Consumers calling recvfrom
      # repeatedly will buffer up all the pieces.
      while data.length > 65507
        rsock.syswrite(data[0..65506])
        rsock.syswrite(Rex::Socket.to_sockaddr(peerhost,peerport))
        data = data - data[0..65506]
      end
      rsock.syswrite(data)
      rsock.syswrite(Rex::Socket.to_sockaddr(peerhost,peerport))
      return true
    else
      return false
    end
  end

end

end; end; end
