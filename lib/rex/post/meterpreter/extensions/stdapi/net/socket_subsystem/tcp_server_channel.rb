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

  include Rex::IO::StreamServer

  #
  # This is a class variable to store all pending client tcp connections which have not been passed
  # off via a call to the respective server tcp channels accept method. The dictionary key is the
  # tcp server channel instance and the values held are an array of pending tcp client channels
  # connected to the tcp server channel.
  #
  @@server_channels = {}

  #
  # This is the request handler which is registered to the respective meterpreter instance via
  # Rex::Post::Meterpreter::Extensions::Stdapi::Net::Socket. All incoming requests from the meterpreter
  # for a 'tcp_channel_open' will be processed here. We create a new TcpClientChannel for each request
  # received and store it in the respective tcp server channels list of new pending client channels.
  # These new tcp client channels are passed off via a call the the tcp server channels accept() method.
  #
  def self.request_handler(client, packet)
    return false unless packet.method == "tcp_channel_open"

    cid       = packet.get_tlv_value( TLV_TYPE_CHANNEL_ID )
    pid       = packet.get_tlv_value( TLV_TYPE_CHANNEL_PARENTID )

    return false if cid.nil? || pid.nil?

    server_channel = client.find_channel(pid)

    return false if server_channel.nil?

    params = Rex::Socket::Parameters.from_hash(
      {
        'Proto'     => 'tcp',
        'Comm'      => server_channel.client
      }
    )

    client_channel = TcpClientChannel.new(client, cid, TcpClientChannel, CHANNEL_FLAG_SYNCHRONOUS, packet, {:sock_params => params})

    client_channel.params = params

    @@server_channels[server_channel] ||= ::Queue.new
    @@server_channels[server_channel].enq(client_channel)

    true
  end

  def self.cls
    CHANNEL_CLASS_STREAM
  end

  #
  # Open a new tcp server channel on the remote end.
  #
  # @return [Channel]
  def self.open(client, params)
    Channel.create(client, 'stdapi_net_tcp_server', self, CHANNEL_FLAG_SYNCHRONOUS,
      [
        {'type'  => TLV_TYPE_LOCAL_HOST, 'value' => params.localhost},
        {'type'  => TLV_TYPE_LOCAL_PORT, 'value' => params.localport}
      ],
      klass_args = {:sock_params => params}
    )
  end

  #
  # Simply initialize this instance.
  #
  def initialize(client, cid, type, flags, response, klass_args)
    super(client, cid, type, flags, response, klass_args)
    @params = klass_args[:sock_params].merge_hash(Socket.params_hash_from_response(response))
    # add this instance to the class variables dictionary of tcp server channels
    @@server_channels[self] ||= ::Queue.new
  end

  #
  # Accept a new tcp client connection form this tcp server channel. This method does not block
  # and returns nil if no new client connection is available.
  #
  def accept_nonblock
    _accept(true)
  end

  #
  # Accept a new tcp client connection form this tcp server channel. This method will block indefinitely
  # if no timeout is specified.
  #
  def accept(opts = {})
    timeout = opts['Timeout']
    if (timeout.nil? || timeout <= 0)
      timeout = 0
    end

    result = nil
    begin
      ::Timeout.timeout(timeout) {
        result = _accept
      }
    rescue Timeout::Error
    end

    result
  end

protected

  def _accept(nonblock = false)
    result = nil

    begin
      channel = @@server_channels[self].deq(nonblock)

      if channel
        result = channel.lsock
      end

      if result != nil && !result.kind_of?(Rex::Socket::Tcp)
        result.extend(Rex::Socket::Tcp)
      end
    rescue ThreadError
      # This happens when there's no clients in the queue
    end

    result
  end

end

end; end; end; end; end; end; end

