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

  ##
  #
  # Factory
  #
  ##

  #
  # Opens a TCP client channel using the supplied parameters.
  #
  def TcpClientChannel.open(client, params)
    Channel.create(client, 'stdapi_net_tcp_client', self, CHANNEL_FLAG_SYNCHRONOUS,
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
      ],
      sock_params: params
    )
  end

  ##
  #
  # Constructor
  #
  ##

  #
  # Passes the channel initialization information up to the base class.
  #
  def initialize(client, cid, type, flags, packet, sock_params: nil)
    super(client, cid, type, flags, packet)

    lsock.extend(SocketInterface)
    lsock.extend(DirectChannelWrite)
    lsock.channel = self

    rsock.extend(SocketInterface)
    rsock.channel = self

    unless sock_params.nil?
      @params = sock_params.merge(Socket.parameters_from_response(packet))
      lsock.extend(Rex::Socket::SslTcp) if sock_params.ssl
    end

    # synchronize access so the socket isn't closed while initializing, this is particularly important for SSL
    lsock.synchronize_access { lsock.initsock(@params) }
    rsock.synchronize_access { rsock.initsock(@params) }
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
    return false if self.cid.nil?

    request = Packet.create_request(COMMAND_ID_STDAPI_NET_SOCKET_TCP_SHUTDOWN)

    request.add_tlv(TLV_TYPE_SHUTDOWN_HOW, how)
    request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)

    client.send_request(request)

    return true
  end

end

end; end; end; end; end; end; end

