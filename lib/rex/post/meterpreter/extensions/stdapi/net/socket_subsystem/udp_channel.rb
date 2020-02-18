# -*- coding: binary -*-
require 'timeout'
require 'rex/sync/thread_safe'
require 'rex/socket/udp'
require 'rex/socket/parameters'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/datagram'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net
module SocketSubsystem

class UdpChannel < Rex::Post::Meterpreter::Datagram

  #
  # We are a datagram channel.
  #
  def self.cls
    CHANNEL_CLASS_DATAGRAM
  end

  #
  # Open a new UDP channel on the remote end. The local host/port are
  # optional, if none are specified the remote end will bind to INADDR_ANY
  # with a random port number. The peer host/port are also optional, if
  # specified all default send(), write() call will sendto the specified peer.
  # If no peer host/port is specified you must use sendto() and specify the
  # remote peer you wish to send to. This effectivly lets us create
  # bound/unbound and connected/unconnected UDP sockets with ease.
  #
  # @return [Channel]
  def self.open(client, params)
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
  def initialize(client, cid, type, flags, response, klass_args)
    super(client, cid, type, flags, response, klass_args)

    lsock.extend(Rex::Socket::Udp)
    lsock.initsock
    lsock.extend(SocketInterface)
    lsock.extend(DirectChannelWrite)
    lsock.channel = self

    # rsock.extend( Rex::Socket::Udp )
    rsock.extend(SocketInterface)
    rsock.channel = self

  end

  #
  # This function is called by Rex::Socket::Udp.sendto and writes data to a
  # specified remote peer host/port via the remote end of the channel.
  #
  # This should work just like a UDPSocket.send method
  #
  # send(mesg, flags, host, port) => numbytes_sent click to toggle source
  # send(mesg, flags, sockaddr_to) => numbytes_sent
  # send(mesg, flags) => numbytes_sent
  #
  def send(buf, flags, a = nil, b = nil)
    host = nil
    port = nil

    if a && b.nil?
      _, host, port = Rex::Socket.from_sockaddr(a)
    elsif a && b
      host = a
      port = b
    end

    addends = nil
    if host && port
      addends = [
        {
          'type'  => TLV_TYPE_PEER_HOST,
          'value' => host
        },
        {
          'type'  => TLV_TYPE_PEER_PORT,
          'value' => port
        }
      ]
    end

    _write(buf, buf.length, addends)
  end

end

end; end; end; end; end; end; end

