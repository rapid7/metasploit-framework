# -*- coding: binary -*-
require 'timeout'
require 'thread'
require 'rex/socket/parameters'
require 'rex/post/meterpreter/channels/stream'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/tcp_client_channel'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net
module SocketSubsystem

class TcpServerChannel < Rex::Post::Meterpreter::Channel

  #
  # This is a class variable to store all pending client tcp connections which have not been passed
  # off via a call to the respective server tcp channels accept method. The dictionary key is the
  # tcp server channel instance and the values held are an array of pending tcp client channels
  # connected to the tcp server channel.
  #
  @@server_channels = {}

  class << self
    include Rex::Post::Meterpreter::InboundPacketHandler

    #
    # This is the request handler which is registerd to the respective meterpreter instance via
    # Rex::Post::Meterpreter::Extensions::Stdapi::Net::Socket. All incoming requests from the meterpreter
    # for a 'tcp_channel_open' will be processed here. We create a new TcpClientChannel for each request
    # received and store it in the respective tcp server channels list of new pending client channels.
    # These new tcp client channels are passed off via a call the the tcp server channels accept() method.
    #
    def request_handler( client, packet )

      if( packet.method == "tcp_channel_open" )

        cid       = packet.get_tlv_value( TLV_TYPE_CHANNEL_ID )
        pid       = packet.get_tlv_value( TLV_TYPE_CHANNEL_PARENTID )
        localhost = packet.get_tlv_value( TLV_TYPE_LOCAL_HOST )
        localport = packet.get_tlv_value( TLV_TYPE_LOCAL_PORT )
        peerhost  = packet.get_tlv_value( TLV_TYPE_PEER_HOST )
        peerport  = packet.get_tlv_value( TLV_TYPE_PEER_PORT )

        if( cid == nil or pid == nil )
          return false
        end

        server_channel = client.find_channel( pid )
        if( server_channel == nil )
          return false
        end

        params = Rex::Socket::Parameters.from_hash(
          {
            'Proto'     => 'tcp',
            'LocalHost' => localhost,
            'LocalPort' => localport,
            'PeerHost'  => peerhost,
            'PeerPort'  => peerport,
            'Comm'      => server_channel.client
          }
        )

        client_channel = TcpClientChannel.new( client, cid, TcpClientChannel, CHANNEL_FLAG_SYNCHRONOUS )

        client_channel.params = params

        if( @@server_channels[server_channel] == nil )
          @@server_channels[server_channel] = []
        end

        @@server_channels[server_channel] << client_channel

        return true
      end

      return false
    end

    def cls
      return CHANNEL_CLASS_STREAM
    end

  end

  #
  # Open a new tcp server channel on the remote end.
  #
  def TcpServerChannel.open(client, params)
    c = Channel.create(client, 'stdapi_net_tcp_server', self, CHANNEL_FLAG_SYNCHRONOUS,
      [
        {
        'type'  => TLV_TYPE_LOCAL_HOST,
        'value' => params.localhost
        },
        {
        'type'  => TLV_TYPE_LOCAL_PORT,
        'value' => params.localport
        }
      ] )
    c.params = params
    c
  end

  #
  # Simply initilize this instance.
  #
  def initialize(client, cid, type, flags)
    super(client, cid, type, flags)
    # add this instance to the class variables dictionary of tcp server channels
    @@server_channels[self] = []
  end

  #
  # Accept a new tcp client connection form this tcp server channel. This method does not block
  # and returns nil if no new client connection is available.
  #
  def accept_nonblock
    result = nil
    if( @@server_channels[self].length > 0 )
      channel = @@server_channels[self].shift
      result = channel.lsock
    end
    return result
  end

  #
  # Accept a new tcp client connection form this tcp server channel. This method will block indefinatly
  # if no timeout is specified.
  #
  def accept( opts={} )
    timeout = opts['Timeout'] || -1
    if( timeout == -1 )
      result = _accept
    else
      begin
        ::Timeout.timeout( timeout ) {
          result = _accept
        }
      rescue Timeout::Error
        result = nil
      end
    end
    return result
  end

protected

  def _accept
    while( true )
      if( @@server_channels[self].empty? )
        Rex::ThreadSafe.sleep( 0.2 )
        next
      end
      result = accept_nonblock
      break if result != nil
    end
    return result
  end

end

end; end; end; end; end; end; end

