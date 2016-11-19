# -*- coding: binary -*-
require 'timeout'
require 'thread'
require 'rex/post/meterpreter/channels/stream'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/named_pipe_client_channel'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net
module SocketSubsystem

class NamedPipeServerChannel < Rex::Post::Meterpreter::Channel

  PIPE_ACCESS_INBOUND  = 0x01
  PIPE_ACCESS_OUTBOUND = 0x02
  PIPE_ACCESS_DUPLEX   = 0x03

  #
  # This is a class variable to store all pending client named pipe connections that
  # have not been passed off via a call to the respective server channel's accept method.
  # The dictionary key is the server channel instance and the values held are an array
  # of pending client channels connected to the server.
  #
  @@server_channels = {}

  #
  # This is the request handler which is registered to the respective meterpreter instance.
  # All incoming requests from the meterpreter for a 'named_pipe_channel_open' will be
  # processed here. We create a new NamedPipeClientChannel for each request received and
  # store it in the respective named pipe server channels list. Named pipes don't behave
  # like TCP when it comes to server functionality, so a server "becomes" a client as soon
  # as a connection is received. Hence, when a client connects, the client channel wraps
  # up the handles from the server channel, and the server creates a new named pipe handle
  # to continue listening on.
  #
  def self.request_handler(client, packet)
    return false unless packet.method == "named_pipe_channel_open"

    cid       = packet.get_tlv_value( TLV_TYPE_CHANNEL_ID )
    pid       = packet.get_tlv_value( TLV_TYPE_CHANNEL_PARENTID )
    name      = packet.get_tlv_value( TLV_TYPE_NAMED_PIPE_NAME )

    server_channel = client.find_channel(pid)

    return false if server_channel.nil?

    client_channel = server_channel.create_client(pid, cid, name)

    @@server_channels[server_channel] ||= ::Queue.new
    @@server_channels[server_channel].enq(client_channel)

    true
  end

  def self.cls
    CHANNEL_CLASS_STREAM
  end

  #
  # Open a new named pipe server channel on the remote end.
  #
  # @return [Channel]
  def self.open(client, params)
    # assume duplex unless specified otherwise
    open_mode = PIPE_ACCESS_DUPLEX
    if params[:open_mode]
      case params[:open_mode]
      when :inbound
        open_mode = PIPE_ACCESS_INBOUND
      when :outbound
        open_mode = PIPE_ACCESS_INBOUND
      end
    end

    c = Channel.create(client, 'stdapi_net_named_pipe_server', self, CHANNEL_FLAG_SYNCHRONOUS,
      [
        {'type'=> TLV_TYPE_NAMED_PIPE_NAME,      'value' => params[:name]},
        {'type'=> TLV_TYPE_NAMED_PIPE_OPEN_MODE, 'value' => open_mode},
        {'type'=> TLV_TYPE_NAMED_PIPE_PIPE_MODE, 'value' => params[:pipe_mode] || 0},
        {'type'=> TLV_TYPE_NAMED_PIPE_COUNT,     'value' => params[:count] || 0},
        {'type'=> TLV_TYPE_NAMED_PIPE_REPEAT,    'value' => params[:repeat] == true}
      ] )
    c.params = params
    c
  end

  #
  # Simply initilize this instance.
  #
  def initialize(client, cid, type, flags)
    super(client, cid, type, flags)
    # add this instance to the class variables dictionary of server channels
    @@server_channels[self] ||= ::Queue.new
  end

  #
  # Accept a new client connection form this server channel. This method does not block
  # and returns nil if no new client connection is available.
  #
  def accept_nonblock
    _accept(true)
  end

  #
  # Accept a new client connection form this server channel. This method will block indefinatly
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

  #
  # This function takes an existing server channel and converts it to a client
  # channel for when a connection appears. If the server is operating in a continuous
  # mode, then it wraps the new listener channel up in the existing server.
  #
  def create_client(parent_id, client_id, pipe_name)

    # we are no long associated with this channel, it'll be wrapped by another
    @client.remove_channel(self)

    client_channel = NamedPipeClientChannel.new(@client, parent_id, NamedPipeClientChannel, CHANNEL_FLAG_SYNCHRONOUS, pipe_name)
    client_channel.params = {
      'Comm'      => @client
    }

    @client.add_channel(client_channel)

    # we don't own the client any more, so we have to let it go
    @cid = client_id
    if @cid
      # a client ID means that there's a new server channel running that we need
      # to bind to as that's the one that's listening.
      @client.add_channel(self)
    end

    client_channel
  end

protected

  def _accept(nonblock = false)
    @@server_channels[self].deq(nonblock)
  end

end

end; end; end; end; end; end; end


