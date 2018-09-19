# -*- coding: binary -*-
require 'thread'

module Rex
module IO

###
#
# This mixin provides the framework and interface for implementing a datagram
# server that can handle incoming datagrams. Datagram servers include this mixin
#
###
module GramServer

  ##
  #
  # Abstract methods
  #
  ##

  ##
  #
  # Default server monitoring and client management implementation follows
  # below.
  #
  ##


  #
  # This callback is notified when a client connection has data that needs to
  # be processed.
  #
  def dispatch_request(client, data)
    if (dispatch_request_proc)
      dispatch_request_proc.call(client, data)
    end
  end

  #
  # This callback is notified when data must be returned to the client
  # @param client [Socket] Client/Socket to receive data
  # @param data [String] Data to be sent to client/socket
  def send_response(client, data)
    if (send_response_proc)
      send_response_proc.call(client, data)
    else
      client.write(data)
    end
  end

  #
  # Start monitoring the listener socket for connections and keep track of
  # all client connections.
  #
  def start
    self.listener_thread = Rex::ThreadFactory.spawn("GramServerListener", false) {
      monitor_listener
    }
  end

  #
  # Terminates the listener monitoring threads and closes all active clients.
  #
  def stop
    self.listener_thread.kill
  end

  #
  # This method waits on the server listener thread
  #
  def wait
    self.listener_thread.join if self.listener_thread
  end

  ##
  #
  # Callback procedures.
  #
  ##

  #
  # This callback procedure can be set and will be called when clients
  # have data to be processed.
  #
  attr_accessor :dispatch_request_proc, :send_response_proc

  attr_accessor :listener_thread# :nodoc:


end

end
end

