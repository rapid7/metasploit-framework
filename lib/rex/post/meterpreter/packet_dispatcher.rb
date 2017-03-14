# -*- coding: binary -*-

require 'rex/post/meterpreter/packet_response_waiter'
require 'rex/logging'
require 'rex/exceptions'
require 'msf/core/payload/uuid'

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

  # Defualt time, in seconds, to wait for a response after sending a packet
  PACKET_TIMEOUT = 600

  # Number of seconds to wait without getting any packets before we try to
  # send a liveness check. A minute should be generous even on the highest
  # latency networks
  #
  # @see #keepalive
  PING_TIME = 60

  # This mutex is used to lock out new commands during an
  # active migration. Unused if this is a passive dispatcher
  attr_accessor :comm_mutex


  # Passive Dispatching
  #
  # @return [Rex::ServiceManager]
  # @return [nil] if this is not a passive dispatcher
  attr_accessor :passive_service

  # @return [Array]
  attr_accessor :send_queue

  # @return [Array]
  attr_accessor :recv_queue

  def initialize_passive_dispatcher
    self.send_queue = []
    self.recv_queue = []
    self.waiters    = []
    self.alive      = true

    # Ensure that there is only one leading and trailing slash on the URI
    resource_uri = "/" + self.conn_id.to_s.gsub(/(^\/|\/$)/, '') + "/"

    self.passive_service = self.passive_dispatcher
    self.passive_service.remove_resource(resource_uri)
    self.passive_service.add_resource(resource_uri,
      'Proc'             => Proc.new { |cli, req| on_passive_request(cli, req) },
      'VirtualDirectory' => true
    )
  end

  def shutdown_passive_dispatcher
    return if not self.passive_service

    # Ensure that there is only one leading and trailing slash on the URI
    resource_uri = "/" + self.conn_id.to_s.gsub(/(^\/|\/$)/, '') + "/"

    self.passive_service.remove_resource(resource_uri)

    # If there are no more resources registered on the service, stop it entirely
    if self.passive_service.resources.empty?
      Rex::ServiceManager.stop_service(self.passive_service)
    end

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

    self.last_checkin = Time.now

    if req.method == 'GET'
      rpkt = send_queue.shift
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

        # Reraise the error to the top-level caller
        raise err if err
      end
    end

    return bytes
  end

  #
  # Sends a packet and waits for a timeout for the given time interval.
  #
  # @param packet [Packet] request to send
  # @param timeout [Integer,nil] seconds to wait for response, or nil to ignore the
  #   response and return immediately
  # @return (see #send_packet_wait_response)
  def send_request(packet, timeout = self.response_timeout)
    response = send_packet_wait_response(packet, timeout)

    if timeout.nil?
      return nil
    elsif response.nil?
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
  # @param packet [Packet] the request packet to send
  # @param timeout [Integer,nil] number of seconds to wait, or nil to wait
  #   forever
  def send_packet_wait_response(packet, timeout)
    # First, add the waiter association for the supplied packet
    waiter = add_response_waiter(packet)

    bytes_written = send_packet(packet)

    # Transmit the packet
    if (bytes_written.to_i <= 0)
      # Remove the waiter if we failed to send the packet.
      remove_response_waiter(waiter)
      return nil
    end

    if not timeout
      return nil
    end

    # Wait for the supplied time interval
    response = waiter.wait(timeout)

    # Remove the waiter from the list of waiters in case it wasn't
    # removed. This happens if the waiter timed out above.
    remove_response_waiter(waiter)

    # wire in the UUID for this, as it should be part of every response
    # packet
    if response && !self.payload_uuid
      uuid = response.get_tlv_value(TLV_TYPE_UUID)
      self.payload_uuid = Msf::Payload::UUID.new({:raw => uuid}) if uuid
    end

    # Return the response packet, if any
    return response
  end

  # Send a ping to the server.
  #
  # Our 'ping' is a check for eof on channel id 0. This method has no side
  # effects and always returns an answer (regardless of the existence of chan
  # 0), which is all that's needed for a liveness check. The answer itself is
  # unimportant and is ignored.
  #
  # @return [void]
  def keepalive
    if @ping_sent
      if Time.now.to_i - last_checkin.to_i > PING_TIME*2
        dlog("No response to ping, session #{self.sid} is dead", LEV_3)
        self.alive = false
      end
    else
      pkt = Packet.create_request('core_channel_eof')
      pkt.add_tlv(TLV_TYPE_CHANNEL_ID, 0)
      add_response_waiter(pkt, Proc.new { @ping_sent = false })
      send_packet(pkt)
      @ping_sent = true
    end
  end

  ##
  #
  # Reception
  #
  ##

  #
  # Simple class to track packets and if they are in-progress or complete.
  #
  class QueuedPacket
    attr_reader :packet
    attr_reader :in_progress

    def initialize(packet, in_progress)
      @packet = packet
      @in_progress = in_progress
    end
  end

  #
  # Monitors the PacketDispatcher's sock for data in its own
  # thread context and parsers all inbound packets.
  #
  def monitor_socket

    # Skip if we are using a passive dispatcher
    return if self.passive_service

    self.comm_mutex = ::Mutex.new

    self.waiters = []

    @pqueue = ::Queue.new
    @ping_sent = false

    # Spawn a thread for receiving packets
    self.receiver_thread = Rex::ThreadFactory.spawn("MeterpreterReceiver", false) do
      while (self.alive)
        begin
          rv = Rex::ThreadSafe.select([ self.sock.fd ], nil, nil, PING_TIME)
          if rv
            packet, in_progress = receive_packet
            @pqueue << QueuedPacket.new(packet, in_progress)
          elsif self.send_keepalives && @pqueue.empty?
            keepalive
          end
        rescue ::Exception => e
          dlog("Exception caught in monitor_socket: #{e.class}: #{e}", 'meterpreter', LEV_1)
          dlog("Call stack: #{e.backtrace.join("\n")}", 'meterpreter', LEV_2)
          self.alive = false
          break
        end
      end
    end

    # Spawn a new thread that monitors the socket
    self.dispatcher_thread = Rex::ThreadFactory.spawn("MeterpreterDispatcher", false) do
      begin
      while (self.alive)
        incomplete = []
        backlog    = []

        backlog << @pqueue.pop
        while(@pqueue.length > 0)
          backlog << @pqueue.pop
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
          if(pkt.packet.response?)
            tmp_command << pkt
            next
          end
          if(pkt.packet.method == "core_channel_close")
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
          if ! dispatch_inbound_packet(pkt.packet, pkt.in_progress)
            # Keep Packets in the receive queue until a handler is registered
            # for them. Packets will live in the receive queue for up to
            # PACKET_TIMEOUT seconds, after which they will be dropped.
            #
            # A common reason why there would not immediately be a handler for
            # a received Packet is in channels, where a connection may
            # open and receive data before anything has asked to read.
            #
            # Also, don't bother saving incomplete packets if we have no handler.
            if (!pkt.in_progress and ::Time.now.to_i - pkt.packet.created_at.to_i < PACKET_TIMEOUT)
              incomplete << pkt
            end
          end

          rescue ::Exception => e
            dlog("Dispatching exception with packet #{pkt.packet}: #{e} #{e.backtrace}", 'meterpreter', LEV_1)
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

        while incomplete.length > 0
          @pqueue << incomplete.shift
        end

        if(@pqueue.length > 100)
          removed = []
          (1..25).each {
            removed << @pqueue.pop
          }
          dlog("Backlog has grown to over 100 in monitor_socket, dropping older packets: #{removed.map{|x| x.inspect}.join(" - ")}", 'meterpreter', LEV_1)
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
  # For not-yet-complete responses, we might not be able to determine
  # the response ID, in that case just let all waiters know that some
  # responses are trickling in.
  #
  def notify_response_waiter(response, in_progress=false)
    handled = false
    self.waiters.each() { |waiter|
      if (in_progress || waiter.waiting_for?(response))
        waiter.notify(response, in_progress)
        remove_response_waiter(waiter) unless in_progress
        handled = true
        break
      end
    }
    return handled
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
  def dispatch_inbound_packet(packet, in_progress=false)
    handled = false

    # Update our last reply time
    self.last_checkin = Time.now

    # If the packet is a response, try to notify any potential
    # waiters
    if packet.response?
      if (notify_response_waiter(packet, in_progress))
        return true
      end
    end

    # Enumerate all of the inbound packet handlers until one handles
    # the packet
    @inbound_handlers.each { |handler|

      handled = nil
      begin

        if packet.response?
          handled = handler.response_handler(self, packet)
        else
          handled = handler.request_handler(self, packet)
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

