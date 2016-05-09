# -*- coding: binary -*-

require 'thread'
require 'rex/socket'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/named_pipe_client_channel'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/named_pipe_server_channel'
require 'rex/logging'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# This class wraps up all the functionality tha tis required to deal with named
# pipe functionality on the target Meterpreter session.
#
###
class NamedPipe

  ##
  #
  # Constructor
  #
  ##

  def initialize(client)
    self.client = client

    client.register_inbound_handler(Rex::Post::Meterpreter::Extensions::Stdapi::Net::SocketSubsystem::NamedPipeServerChannel)

  end

  def shutdown
    client.deregister_inbound_handler(Rex::Post::Meterpreter::Extensions::Stdapi::Net::SocketSubsystem::NamedPipeServerChannel)
  end

  ##
  #
  # Factory
  #
  ##

  #
  # Creates an arbitrary client socket channel using the information supplied
  # in the socket parameters instance.  The +params+ argument is expected to be
  # of type Rex::Socket::Parameters.
  #
  def create(params={})
    res = nil

    if params[:listen] == true
      res = create_named_pipe_server_channel(params)
    else
      res = create_named_pipe_client_channel(params)
    end

    return res
  end

  #
  # Create a named pipe server channel.
  #
  def create_named_pipe_server_channel(params)
      SocketSubsystem::NamedPipeServerChannel.open(client, params)
  end

  #
  # Creates a named pipe client channel.
  #
  def create_named_pipe_client_channel(params)
    begin
      channel = SocketSubsystem::NamedPipeClientChannel.open(client, params)
      if channel != nil
        return channel.lsock
      end
      return nil
    rescue ::Rex::Post::Meterpreter::RequestError => e
      case e.code
      when 10000 .. 10100
        raise ::Rex::ConnectionError.new
      end
      raise e
    end
  end

protected

  attr_accessor :client # :nodoc:

end

end; end; end; end; end; end

