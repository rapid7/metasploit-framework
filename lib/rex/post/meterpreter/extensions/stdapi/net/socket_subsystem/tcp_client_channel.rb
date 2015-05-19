# -*- coding: binary -*-

require 'thread'
require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/stream'
require 'rex/post/meterpreter/extensions/stdapi/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net
module SocketSubsystem

###
#
# This class represents a logical TCP client connection
# that is established from the remote machine and tunnelled
# through the established meterpreter connection, similar to an
# SSH port forward.
#
###
class TcpClientChannel < Rex::Post::Meterpreter::Stream

  class << self
    def cls
      return CHANNEL_CLASS_STREAM
    end
  end

  module SocketInterface
    def type?
      'tcp'
    end

    def getsockname
      return super if not channel
      # Find the first host in our chain (our address)
      hops = 0
      csock = channel.client.sock
      while(csock.respond_to?('channel'))
        csock = csock.channel.client.sock
        hops += 1
      end
      tmp,caddr,cport = csock.getsockname
      tmp,raddr,rport = csock.getpeername
      maddr,mport = [ channel.params.localhost, channel.params.localport ]
      [ tmp, "#{caddr}#{(hops > 0) ? "-_#{hops}_" : ""}-#{raddr}", "#{mport}" ]
    end

    def getpeername
      return super if not channel
      tmp,caddr,cport = channel.client.sock.getpeername
      maddr,mport = [ channel.params.peerhost, channel.params.peerport ]
      [ tmp, "#{maddr}", "#{mport}" ]
    end

    attr_accessor :channel
  end

  #
  # Simple mixin for lsock in order to help avoid a ruby interpreter issue with ::Socket.pair
  # Instead of writing to the lsock, reading from the rsock and then writing to the channel,
  # we use this mixin to directly write to the channel.
  #
  # Note: This does not work with OpenSSL as OpenSSL is implemented natively and requires a real
  # socket to write to and we cant intercept the sockets syswrite at a native level.
  #
  # Note: The deadlock only seems to effect the Ruby build for cygwin.
  #
  module DirectChannelWrite

    def syswrite( buf )
      channel._write( buf )
    end

    attr_accessor :channel
  end

  ##
  #
  # Factory
  #
  ##

  #
  # Opens a TCP client channel using the supplied parameters.
  #
  def TcpClientChannel.open(client, params)
    c = Channel.create(client, 'stdapi_net_tcp_client', self, CHANNEL_FLAG_SYNCHRONOUS,
      [
        {
          'type'  => TLV_TYPE_PEER_HOST,
          'value' => params.peerhost
        },
        {
          'type'  => TLV_TYPE_PEER_PORT,
          'value' => params.peerport
        },
        {
          'type'  => TLV_TYPE_LOCAL_HOST,
          'value' => params.localhost
        },
        {
          'type'  => TLV_TYPE_LOCAL_PORT,
          'value' => params.localport
        },
        {
          'type'  => TLV_TYPE_CONNECT_RETRIES,
          'value' => params.retries
        }
      ])
    c.params = params
    c
  end

  ##
  #
  # Constructor
  #
  ##

  #
  # Passes the channel initialization information up to the base class.
  #
  def initialize( client, cid, type, flags )
    super( client, cid, type, flags )

    lsock.extend( SocketInterface )
    lsock.extend( DirectChannelWrite )
    lsock.channel = self

    rsock.extend( SocketInterface )
    rsock.channel = self

  end

  #
  # Closes the write half of the connection.
  #
  def close_write
    return shutdown(1)
  end

  #
  # Shutdown the connection
  #
  # 0 -> future reads
  # 1 -> future sends
  # 2 -> both
  #
  def shutdown(how = 1)
    request = Packet.create_request('stdapi_net_socket_tcp_shutdown')

    request.add_tlv(TLV_TYPE_SHUTDOWN_HOW, how)
    request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)

    response = client.send_request(request)

    return true
  end

  #
  # Wrap the _write() call in order to catch some common, but harmless Windows exceptions
  #
  def _write(*args)
    begin
      super(*args)
    rescue ::Rex::Post::Meterpreter::RequestError => e
      case e.code
      when 10000 .. 10100
        raise ::Rex::ConnectionError.new
      end
    end
  end
end

end; end; end; end; end; end; end

