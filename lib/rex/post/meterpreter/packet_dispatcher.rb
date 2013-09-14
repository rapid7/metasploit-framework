#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/packet_response_waiter'
require 'rex/logging'
require 'rex/exceptions'

module Rex
module Post
module Meterpreter

###
#
# Exception thrown when a request fails.
#
###
class RequestError < ArgumentError
  def initialize(method, einfo, ecode=nil)
    @method = method
    @result = einfo
    @code   = ecode || einfo
  end

  def to_s
    "#{@method}: Operation failed: #{@result}"
  end

  # The method that failed.
  attr_reader :method

  # The error result that occurred, typically a windows error message.
  attr_reader :result

  # The error result that occurred, typically a windows error code.
  attr_reader :code
end

###
#
# Handles packet transmission, reception, and correlation,
# and processing
#
###
module PacketDispatcher

  PacketTimeout = 600

  ##
  #
  # Synchronization
  #
  ##
  attr_accessor :comm_mutex


  ##
  #
  #
  # Passive Dispatching
  #
  ##
  attr_accessor :passive_service, :send_queue, :recv_queue

  def initialize_passive_dispatcher
    self.send_queue = []
    self.recv_queue = []
    self.waiters    = []
    self.alive      = true

    self.passive_service = self.passive_dispatcher
    self.passive_service.remove_resource("/" + self.conn_id  + "/")
    self.passive_service.add_resource("/" + self.conn_id + "/",
      'Proc'             => Proc.new { |cli, req| on_passive_request(cli, req) },
      'VirtualDirectory' => true
    )
  end

  def shutdown_passive_dispatcher
    return if not self.passive_service
    self.passive_service.remove_resource("/" + self.conn_id  + "/")

    self.alive      = false
    self.send_queue = []
    self.recv_queue = []
    self.waiters    = []

    self.passive_service = nil
  end

  def on_passive_request(cli, req)

    begin

    resp = Rex::Proto::Http::Response.new(200, "OK")
    resp['Content-Type'] = 'application/octet-stream'
    resp['Connection']   = 'close'

    # If the first 4 bytes are "RECV", return the oldest packet from the outbound queue
    if req.body[0,4] == "RECV"
      rpkt = send_queue.pop
      resp.body = rpkt || ''
      begin
        cli.send_response(resp)
      rescue ::Exception => e
        send_queue.unshift(rpkt) if rpkt
        elog("Exception sending a reply to the reader request: #{cli.inspect} #{e.class} #{e} #{e.backtrace}")
      end
    else
      resp.body = ""
      if req.body and req.body.length > 0
        packet = Packet.new(0)
        packet.from_r(req.body)
        dispatch_inbound_packet(packet)
      end
      cli.send_response(resp)
    end

    # Force a closure for older WinInet implementations
    self.passive_service.close_client( cli )

    rescue ::Exception => e
      elog("Exception handling request: #{cli.inspect} #{req.inspect} #{e.class} #{e} #{e.backtrace}")
    end
  end

  ##
  #
  # Transmission
  #
  ##

  #
  # Sends a packet without waiting for a response.
  #
  def send_packet(packet, completion_routine = nil, completion_param = nil)
    if (completion_routine)
      add_response_waiter(packet, completion_routine, completion_param)
    end

    bytes = 0
    raw   = packet.to_r
    err   = nil

    # Short-circuit send when using a passive dispatcher
    if self.passive_service
      send_queue.push(raw)
      return raw.size # Lie!
    end

    if (raw)

      # This mutex is used to lock out new commands during an
      # active migration.

      self.comm_mutex.synchronize do
        begin
          bytes = self.sock.write(raw)
        rescue ::Exception => e
          err = e
        end
      end

      if bytes.to_i == 0
        # Mark the session itself as dead
        self.alive = false

        # Indicate that the dispatcher should shut down too
        @finish = true

        # Reraise the error to the top-level caller
        raise err if err
      end
    end

    return bytes
  end

  #
  # Sends a packet and waits for a timeout for the given time interval.
  #
  def send_request(packet, t = self.response_timeout)

    if not t
      send_packet(packet)
      return nil
    end

    response = send_packet_wait_response(packet, t)

    if (response == nil)
      raise TimeoutError.new("Send timed out")
    elsif (response.result != 0)
      einfo = lookup_error(response.result)
      e = RequestError.new(packet.method, einfo, response.result)

      e.set_backtrace(caller)

      raise e
    end

    return response
  end

  #
  # Transmits a packet and waits for a response.
  #
  def send_packet_wait_response(packet, t)
    # First, add the waiter association for the supplied packet
    waiter = add_response_waiter(packet)

    # Transmit the packet
    if (send_packet(packet).to_i <= 0)
      # Remove the waiter if we failed to send the packet.
      remove_response_waiter(waiter)
      return nil
    end

    # Wait for the supplied time interval
    waiter.wait(t)

    # Remove the waiter from the list of waiters in case it wasn't
    # removed
    remove_response_waiter(waiter)

    # Return the response packet, if any
    return waiter.response
  end

  ##
  #
  # Reception
  #
  ##
  #
  # Monitors the PacketDispatcher's sock for data in its own
  # thread context and parsers all inbound packets.
  #
  def monitor_socket

    # Skip if we are using a passive dispatcher
    return if self.passive_service

    self.comm_mutex = ::Mutex.new

    self.waiters = []

    @pqueue = []
    @finish = false
    @last_recvd = Time.now
    @ping_sent = false

    self.alive = true

    # Spawn a thread for receiving packets
    self.receiver_thread = Rex::ThreadFactory.spawn("MeterpreterReceiver", false) do
      while (self.alive)
        begin
          rv = Rex::ThreadSafe.select([ self.sock.fd ], nil, nil, 0.25)
          ping_time = 60
          # If there's nothing to read, and it's been awhile since we
          # saw a packet, we need to send a ping.  We wait
          # ping_time*2 seconds before deciding a session is dead.
          if (not rv and self.send_keepalives and Time.now - @last_recvd > ping_time)
            # If the queue is empty and we've already sent a
            # keepalive without getting a reply, then this
            # session is hosed, and we should give up on it.
            if @ping_sent and @pqueue.empty? and (Time.now - @last_recvd > ping_time * 2)
              dlog("No response to ping, session #{self.sid} is dead", LEV_3)
              self.alive = false
              @finish = true
              break
            end
            # Let the packet queue processor finish up before
            # we send a ping.
            if not @ping_sent and @pqueue.empty?
              # Our 'ping' is actually just a check for eof on
              # channel id 0.  This method has no side effects
              # and always returns an answer (regardless of the
              # existence of chan 0), which is all that's
              # needed for a liveness check.  The answer itself
              # is unimportant and is ignored.
              pkt = Packet.create_request('core_channel_eof')
              pkt.add_tlv(TLV_TYPE_CHANNEL_ID, 0)
              waiter = Proc.new { |response, param|
                  @ping_sent = false
                  @last_recvd = Time.now
                }
              send_packet(pkt, waiter)
              @ping_sent = true
            end
            next
          end
          next if not rv
          packet = receive_packet
          @pqueue << packet if packet
          @last_recvd = Time.now
        rescue ::Exception
          dlog("Exception caught in monitor_socket: #{$!}", 'meterpreter', LEV_1)
          @finish = true
          self.alive = false
          break
        end
      end
    end

    # Spawn a new thread that monitors the socket
    self.dispatcher_thread = Rex::ThreadFactory.spawn("MeterpreterDispatcher", false) do
      begin
      # Whether we're finished or not is determined by the receiver
      # thread above.
      while(not @finish)
        if(@pqueue.empty?)
          ::IO.select(nil, nil, nil, 0.10)
          next
        end

        incomplete = []
        backlog    = []

        while(@pqueue.length > 0)
          backlog << @pqueue.shift
        end

        #
        # Prioritize message processing here
        # 1. Close should always be processed at the end
        # 2. Command responses always before channel data
        #

        tmp_command = []
        tmp_channel = []
        tmp_close   = []
        backlog.each do |pkt|
          if(pkt.response?)
            tmp_command << pkt
            next
          end
          if(pkt.method == "core_channel_close")
            tmp_close << pkt
            next
          end
          tmp_channel << pkt
        end

        backlog = []
        backlog.push(*tmp_command)
        backlog.push(*tmp_channel)
        backlog.push(*tmp_close)


        #
        # Process the message queue
        #

        backlog.each do |pkt|

          begin
          if ! dispatch_inbound_packet(pkt)
            # Only requeue packets newer than the timeout
            if (::Time.now.to_i - pkt.created_at.to_i < PacketTimeout)
              incomplete << pkt
            end
          end

          rescue ::Exception => e
            dlog("Dispatching exception with packet #{pkt}: #{e} #{e.backtrace}", 'meterpreter', LEV_1)
          end
        end

        # If the backlog and incomplete arrays are the same, it means
        # dispatch_inbound_packet wasn't able to handle any of the
        # packets. When that's the case, we can get into a situation
        # where @pqueue is not empty and, since nothing else bounds this
        # loop, we spin CPU trying to handle packets that can't be
        # handled. Sleep here to treat that situation as though the
        # queue is empty.
        if (backlog.length > 0 && backlog.length == incomplete.length)
          ::IO.select(nil, nil, nil, 0.10)
        end

        @pqueue.unshift(*incomplete)

        if(@pqueue.length > 100)
          dlog("Backlog has grown to over 100 in monitor_socket, dropping older packets: #{@pqueue[0 .. 25].map{|x| x.inspect}.join(" - ")}", 'meterpreter', LEV_1)
          @pqueue = @pqueue[25 .. 100]
        end
      end
      rescue ::Exception => e
        dlog("Exception caught in monitor_socket dispatcher: #{e.class} #{e} #{e.backtrace}", 'meterpreter', LEV_1)
      ensure
        self.receiver_thread.kill if self.receiver_thread
      end
    end
  end


  #
  # Parses data from the dispatcher's sock and returns a Packet context
  # once a full packet has been received.
  #
  def receive_packet
    return parser.recv(self.sock)
  end

  #
  # Stop the monitor
  #
  def monitor_stop
    if(self.receiver_thread)
      self.receiver_thread.kill
      self.receiver_thread = nil
    end

    if(self.dispatcher_thread)
      self.dispatcher_thread.kill
      self.dispatcher_thread = nil
    end
  end

  ##
  #
  # Waiter registration
  #
  ##

  #
  # Adds a waiter association with the supplied request packet.
  #
  def add_response_waiter(request, completion_routine = nil, completion_param = nil)
    waiter = PacketResponseWaiter.new(request.rid, completion_routine, completion_param)

    self.waiters << waiter

    return waiter
  end

  #
  # Notifies a whomever is waiting for a the supplied response,
  # if anyone.
  #
  def notify_response_waiter(response)
    self.waiters.each() { |waiter|
      if (waiter.waiting_for?(response))
        waiter.notify(response)

        remove_response_waiter(waiter)

        break
      end
    }
  end

  #
  # Removes a waiter from the list of waiters.
  #
  def remove_response_waiter(waiter)
    self.waiters.delete(waiter)
  end

  ##
  #
  # Dispatching
  #
  ##

  #
  # Initializes the inbound handlers.
  #
  def initialize_inbound_handlers
    @inbound_handlers = []
  end

  #
  # Dispatches and processes an inbound packet.  If the packet is a
  # response that has an associated waiter, the waiter is notified.
  # Otherwise, the packet is passed onto any registered dispatch
  # handlers until one returns success.
  #
  def dispatch_inbound_packet(packet, client = nil)
    handled = false

    # If no client context was provided, return self as PacketDispatcher
    # is a mixin for the Client instance
    if (client == nil)
      client = self
    end

    # If the packet is a response, try to notify any potential
    # waiters
    if ((resp = packet.response?))
      if (notify_response_waiter(packet))
        return true
      end
    end

    # Enumerate all of the inbound packet handlers until one handles
    # the packet
    @inbound_handlers.each { |handler|

      handled = nil
      begin

      if ! resp
        handled = handler.request_handler(client, packet)
      else
        handled = handler.response_handler(client, packet)
      end

      rescue ::Exception => e
        dlog("Exception caught in dispatch_inbound_packet: handler=#{handler} #{e.class} #{e} #{e.backtrace}", 'meterpreter', LEV_1)
        return true
      end

      if (handled)
        break
      end
    }
    return handled
  end

  #
  # Registers an inbound packet handler that implements the
  # InboundPacketHandler interface.
  #
  def register_inbound_handler(handler)
    @inbound_handlers << handler
  end

  #
  # Deregisters a previously registered inbound packet handler.
  #
  def deregister_inbound_handler(handler)
    @inbound_handlers.delete(handler)
  end

protected

  attr_accessor :receiver_thread # :nodoc:
  attr_accessor :dispatcher_thread # :nodoc:
  attr_accessor :waiters # :nodoc:
end

end; end; end

