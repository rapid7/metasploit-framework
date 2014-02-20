# -*- coding: binary -*-
require 'timeout'
require 'rex/sync/thread_safe'
require 'rex/socket/udp'
require 'rex/socket/parameters'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/channel'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net
module SocketSubsystem

class UdpChannel < Rex::Post::Meterpreter::Channel

  #
  # We inclue Rex::Socket::Udp as this channel is effectivly a UDP socket.
  #
  include Rex::Socket::Udp

  #
  # We are a datagram channel.
  #
  class << self
    def cls
      return CHANNEL_CLASS_DATAGRAM
    end
  end

  #
  # Open a new UDP channel on the remote end. The local host/port are optional, if none are specified
  # the remote end will bind to INADDR_ANY with a random port number. The peer host/port are also
  # optional, if specified all default send(), write() call will sendto the specified peer. If no peer
  # host/port is specified you must use sendto() and specify the remote peer you wish to send to. This
  # effectivly lets us create bound/unbound and connected/unconnected UDP sockets with ease.
  #
  def UdpChannel.open(client, params)
    c = Channel.create(client, 'stdapi_net_udp_client', self, CHANNEL_FLAG_SYNCHRONOUS,
    [
      {
        'type'  => TLV_TYPE_LOCAL_HOST,
        'value' => params.localhost
      },
      {
        'type'  => TLV_TYPE_LOCAL_PORT,
        'value' => params.localport
      },
      {
        'type'  => TLV_TYPE_PEER_HOST,
        'value' => params.peerhost
      },
      {
        'type'  => TLV_TYPE_PEER_PORT,
        'value' => params.peerport
      }
    ] )
    c.params = params
    c
  end

  #
  # Simply initialize this instance.
  #
  def initialize(client, cid, type, flags)
    super(client, cid, type, flags)
    # the instance variable that holds all incoming datagrams.
    @datagrams = []
  end

  #
  # We overwrite Rex::Socket::Udp.timed_read in order to avoid the call to Kernel.select
  # which wont be of use as we are not a natively backed ::Socket or ::IO instance.
  #
  def timed_read( length=65535, timeout=def_read_timeout )
    result = ''

    begin
      Timeout.timeout( timeout ) {
        while( true )
          if( @datagrams.empty? )
            Rex::ThreadSafe.sleep( 0.2 )
            next
          end
          result = self.read( length )
          break
        end
      }
    rescue Timeout::Error
      result = ''
    end

    return result
  end

  #
  # We overwrite Rex::Socket::Udp.recvfrom in order to correctly hand out the
  # datagrams which the remote end of this channel has received and are in the
  # queue.
  #
  def recvfrom( length=65535, timeout=def_read_timeout )
    result = nil
    # force a timeout on the wait for an incoming datagram
    begin
      Timeout.timeout( timeout ) {
        while( true )
          # wait untill we have at least one datagram in the queue
          if( @datagrams.empty? )
            Rex::ThreadSafe.sleep( 0.2 )
            next
          end
          # grab the oldest datagram we have received...
          result = @datagrams.shift
          # break as we have a result...
          break
        end
      }
    rescue Timeout::Error
      result = nil
    end
    # if no result return nothing
    if( result == nil )
      return [ '', nil, nil ]
    end
    # get the data from this datagram
    data = result[0]
    # if its only a partial read of this datagram, slice it, loosing the remainder.
    result[0] = data[0,length-1] if data.length > length
    # return the result in the form [ data, host, port ]
    return result
  end

  #
  # Overwrite the low level sysread to read data off our datagram queue. Calls
  # to read() will end up calling this.
  #
  def sysread( length )
    result = self.recvfrom( length )
    return result[0]
  end

  #
  # Overwrite the low level syswrite to write data to the remote end of the channel.
  # Calls to write() will end up calling this.
  #
  def syswrite( buf )
    return _write( buf )
  end

  #
  # This function is called by Rex::Socket::Udp.sendto and writes data to a specified
  # remote peer host/port via the remote end of the channel.
  #
  def send( buf, flags, saddr )
    af, peerhost, peerport = Rex::Socket.from_sockaddr( saddr )

    addends = [
      {
        'type'  => TLV_TYPE_PEER_HOST,
        'value' => peerhost
      },
      {
        'type'  => TLV_TYPE_PEER_PORT,
        'value' => peerport
      }
    ]

    return _write( buf, buf.length, addends )
  end

  #
  # The channels direct io write handler for any incoming data from the remote end
  # of the channel. We extract the data and peer host/port, and save this to a queue
  # of incoming datagrams which are passed out via calls to self.recvfrom()
  #
  def dio_write_handler( packet, data )

    peerhost = packet.get_tlv_value( TLV_TYPE_PEER_HOST )
    peerport = packet.get_tlv_value( TLV_TYPE_PEER_PORT )

    if( peerhost and peerport )
      @datagrams << [ data, peerhost, peerport ]
      return true
    end

    return false
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

