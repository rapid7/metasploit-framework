# -*- coding: binary -*-

require 'rex/post/meterpreter/command_mapper'
require 'rex/post/meterpreter/packet_response_waiter'
require 'rex/exceptions'
require 'pathname'

module Rex
module Post
module Meterpreter

###
#
# Exception thrown when a request fails.
#
###
class RequestError < ArgumentError
  def initialize(command_id, einfo, ecode=nil)
    command_name = Rex::Post::Meterpreter::CommandMapper.get_command_name(command_id)

    @method = command_name || "##{command_id}"
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

  # Default time, in seconds, to wait for a response after sending a packet
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

  # The guid that identifies an active Meterpreter session
  attr_accessor :session_guid

  # This contains the key material used for TLV encryption
  attr_accessor :tlv_enc_key

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
    self.send_queue   = []
    self.recv_queue   = []
    self.waiters      = []
    self.alive        = true
  end

  def shutdown_passive_dispatcher
    self.alive      = false
    self.send_queue = []
    self.recv_queue = []
    self.waiters    = []
  end

  def on_passive_request(cli, req)
    begin
      self.last_checkin = ::Time.now
      resp = send_queue.shift
      cli.send_response(resp)
    rescue => e
      send_queue.unshift(resp) if resp
      elog("Exception sending a reply to the reader request #{cli.inspect}", error: e)
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
  def send_packet(packet, opts={})
    if self.pivot_session
      opts[:session_guid] = self.session_guid
      opts[:tlv_enc_key] = self.tlv_enc_key
      return self.pivot_session.send_packet(packet, opts)
    end

    if opts[:completion_routine]
      add_response_waiter(packet, opts[:completion_routine], opts[:completion_param])
    end

    session_guid = self.session_guid
    tlv_enc_key = self.tlv_enc_key

    # if a session guid is provided, use all the details provided
    if opts[:session_guid]
      session_guid = opts[:session_guid]
      tlv_enc_key = opts[:tlv_enc_key]
    end

    log_packet(packet, :send)

    bytes = 0
    raw   = packet.to_r(session_guid, tlv_enc_key)
    err   = nil

    # Short-circuit send when using a passive dispatcher
    if self.passive_service
      send_queue.push(raw)
      return raw.size # Lie!
    end

    if raw
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
      raise Rex::TimeoutError.new("Send timed out")
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
    if packet.type == PACKET_TYPE_REQUEST && commands.present?
      # XXX: Remove this condition once the payloads gem has had another major version bump from 2.x to 3.x and
      # rapid7/metasploit-payloads#451 has been landed to correct the `enumextcmd` behavior on Windows. Until then, skip
      # proactive validation of Windows core commands. This is not the only instance of this workaround.
      windows_core = base_platform == 'windows' && (packet.method - (packet.method % COMMAND_ID_RANGE)) == Rex::Post::Meterpreter::ClientCore.extension_id

      unless windows_core || commands.include?(packet.method)
        if (ext_name = Rex::Post::Meterpreter::ExtensionMapper.get_extension_name(packet.method))
          unless ext.aliases.include?(ext_name)
            raise RequestError.new(packet.method, "The command requires the #{ext_name} extension to be loaded")
          end
        end
        raise RequestError.new(packet.method, "The command is not supported by this Meterpreter type (#{session_type})")
      end
    end

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
      if ::Time.now.to_i - last_checkin.to_i > PING_TIME*2
        dlog("No response to ping, session #{self.sid} is dead", LEV_3)
        self.alive = false
      end
    else
      pkt = Packet.create_request(COMMAND_ID_CORE_CHANNEL_EOF)
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

  def pivot_keepalive_start
    return unless self.send_keepalives
    self.receiver_thread = Rex::ThreadFactory.spawn("PivotKeepalive", false) do
      while self.alive
        begin
          Rex::sleep(PING_TIME)
          keepalive
        rescue ::Exception => e
          dlog("Exception caught in pivot keepalive: #{e.class}: #{e}", 'meterpreter', LEV_1)
          dlog("Call stack: #{e.backtrace.join("\n")}", 'meterpreter', LEV_2)
          self.alive = false
          break
        end
      end
    end
  end

  #
  # Monitors the PacketDispatcher's sock for data in its own
  # thread context and parsers all inbound packets.
  #
  def monitor_socket

    # Skip if we are using a passive dispatcher
    return if self.passive_service

    # redirect to pivot keepalive if we're a pivot session
    return pivot_keepalive_start if self.pivot_session

    self.comm_mutex = ::Mutex.new

    self.waiters = []

    # This queue is where the new incoming packets end up
    @new_packet_queue = ::Queue.new
    # This is where we put packets that aren't new, but haven't
    # yet been handled.
    @incomplete_queue = ::Queue.new
    @ping_sent = false

    # Spawn a thread for receiving packets
    self.receiver_thread = Rex::ThreadFactory.spawn("MeterpreterReceiver", false) do
      while (self.alive)
        begin
          rv = Rex::ThreadSafe.select([ self.sock.fd ], nil, nil, PING_TIME)
          if rv
            packet = receive_packet
            # Always enqueue the new packets onto the new packet queue
            @new_packet_queue << decrypt_inbound_packet(packet) if packet
          elsif self.send_keepalives && @new_packet_queue.empty?
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
        # This is where we'll store incomplete packets on
        # THIS iteration
        incomplete = []
        # The backlog is the full list of packets that aims
        # to be handled this iteration
        backlog    = []

        # If we have any left over packets from the previous
        # iteration, we need to prioritise them over the new
        # packets. If we don't do this, then we end up in
        # situations where data on channels can be processed
        # out of order. We don't do a blocking wait here via
        # the .pop method because we don't want to block, we
        # just want to dump the queue.
        while @incomplete_queue.length > 0
          backlog << @incomplete_queue.pop
        end

        # If the backlog is empty, we don't have old/stale
        # packets hanging around, so perform a blocking wait
        # for the next packet
        backlog << @new_packet_queue.pop if backlog.length == 0
        # At this point we either received a packet off the wire
        # or we had a backlog to process. In either case, we
        # perform a non-blocking queue dump to fill the backlog
        # with every packet we have.
        while @new_packet_queue.length > 0
          backlog << @new_packet_queue.pop
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
          if(pkt.method == COMMAND_ID_CORE_CHANNEL_CLOSE)
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
          unless dispatch_inbound_packet(pkt)
            # Keep Packets in the receive queue until a handler is registered
            # for them. Packets will live in the receive queue for up to
            # PACKET_TIMEOUT seconds, after which they will be dropped.
            #
            # A common reason why there would not immediately be a handler for
            # a received Packet is in channels, where a connection may
            # open and receive data before anything has asked to read.
            if (::Time.now.to_i - pkt.created_at.to_i < PACKET_TIMEOUT)
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
        # where @new_packet_queue is not empty and, since nothing else bounds this
        # loop, we spin CPU trying to handle packets that can't be
        # handled. Sleep here to treat that situation as though the
        # queue is empty.
        if (backlog.length > 0 && backlog.length == incomplete.length)
          ::IO.select(nil, nil, nil, 0.10)
        end

        # If we have any packets that weren't handled, they go back
        # on the incomplete queue so that they're prioritised over
        # new packets that are coming in off the wire.
        dlog("Requeuing #{incomplete.length} packet(s)", 'meterpreter', LEV_1) if incomplete.length > 0
        while incomplete.length > 0
          @incomplete_queue << incomplete.shift
        end

        # If the old queue of packets gets too big...
        if(@incomplete_queue.length > 100)
          removed = []
          # Drop a bunch of them.
          (1..25).each {
            removed << @incomplete_queue.pop
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
    packet = parser.recv(self.sock)
    if packet
      packet.parse_header!
      if self.session_guid == NULL_GUID
        self.session_guid = packet.session_guid.dup
      end
    end
    packet
  end

  #
  # Stop the monitor
  #
  def monitor_stop
    if self.receiver_thread
      self.receiver_thread.kill
      self.receiver_thread.join
      self.receiver_thread = nil
    end

    if self.dispatcher_thread
      self.dispatcher_thread.kill
      self.dispatcher_thread.join
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
    if self.pivot_session
      return self.pivot_session.add_response_waiter(request, completion_routine, completion_param)
    end

    waiter = PacketResponseWaiter.new(request.rid, completion_routine, completion_param)

    self.waiters << waiter

    return waiter
  end

  #
  # Notifies a whomever is waiting for a the supplied response,
  # if anyone.
  #
  def notify_response_waiter(response)
    if self.pivot_session
      return self.pivot_session.notify_response_waiter(response)
    end

    handled = false
    self.waiters.each() { |waiter|
      if (waiter.waiting_for?(response))
        waiter.notify(response)
        remove_response_waiter(waiter)
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
    if self.pivot_session
      self.pivot_session.remove_response_waiter(waiter)
    else
      self.waiters.delete(waiter)
    end
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
  # Decrypt the given packet with the appropriate key depending on
  # if this session is a pivot session or not.
  #
  def decrypt_inbound_packet(packet)
    pivot_session = self.find_pivot_session(packet.session_guid)
    tlv_enc_key = self.tlv_enc_key
    tlv_enc_key = pivot_session.pivoted_session.tlv_enc_key if pivot_session
    packet.from_r(tlv_enc_key)
    packet
  end

  #
  # Dispatches and processes an inbound packet.  If the packet is a
  # response that has an associated waiter, the waiter is notified.
  # Otherwise, the packet is passed onto any registered dispatch
  # handlers until one returns success.
  #
  def dispatch_inbound_packet(packet)
    handled = false

    log_packet(packet, :recv)

    # Update our last reply time
    self.last_checkin = ::Time.now

    pivot_session = self.find_pivot_session(packet.session_guid)
    pivot_session.pivoted_session.last_checkin = self.last_checkin if pivot_session

    # If the packet is a response, try to notify any potential
    # waiters
    if packet.response? && notify_response_waiter(packet)
      return true
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

  def initialize_tlv_logging(opt)
    self.tlv_logging_error_occured = false
    self.tlv_log_file = nil
    self.tlv_log_file_path = nil
    self.tlv_log_output = :none

    if opt.casecmp?('console') || opt.casecmp?('true')
      self.tlv_log_output = :console
    elsif opt.start_with?('file:')
      self.tlv_log_output = :file
      self.tlv_log_file_path = opt.split('file:').last
    end
  end

protected

  attr_accessor :receiver_thread # :nodoc:
  attr_accessor :dispatcher_thread # :nodoc:
  attr_accessor :waiters # :nodoc:

  attr_accessor :tlv_log_output # :nodoc:
  attr_accessor :tlv_log_file # :nodoc:
  attr_accessor :tlv_log_file_path # :nodoc:
  attr_accessor :tlv_logging_error_occured # :nodoc:

  def shutdown_tlv_logging
    self.tlv_log_output = :none
    self.tlv_log_file.close unless self.tlv_log_file.nil?
    self.tlv_log_file = nil
    self.tlv_log_file_path = nil
  end

  def log_packet(packet, packet_type)
    # if we previously failed to log, return
    return if self.tlv_logging_error_occured || self.tlv_log_output == :none

    if self.tlv_log_output == :console
      log_packet_to_console(packet, packet_type)
    elsif self.tlv_log_output == :file
      log_packet_to_file(packet, packet_type)
    end
  end

  def log_packet_to_console(packet, packet_type)
    if packet_type == :send
      print "\n%redSEND%clr: #{packet.inspect}\n"
    elsif packet_type == :recv
      print "\n%bluRECV%clr: #{packet.inspect}\n"
    end
  end

  def log_packet_to_file(packet, packet_type)
    pathname = ::Pathname.new(self.tlv_log_file_path.split('file:').last)

    begin
      if self.tlv_log_file.nil? || self.tlv_log_file.path != pathname.to_s
        self.tlv_log_file.close unless self.tlv_log_file.nil?

        self.tlv_log_file = ::File.open(pathname, 'a+')
      end

      if packet_type == :recv
        self.tlv_log_file.puts("\nRECV: #{packet.inspect}\n")
      elsif packet_type == :send
        self.tlv_log_file.puts("\nSEND: #{packet.inspect}\n")
      end
    rescue ::StandardError => e
      self.tlv_logging_error_occured = true
      print_error "Failed writing to TLV Log File: #{pathname} with error: #{e.message}. Turning off logging for this session: #{self.inspect}..."
      elog(e)
      shutdown_tlv_logging
      return
    end
  end
end

module HttpPacketDispatcher
  def initialize_passive_dispatcher
    super

    # Ensure that there is only one leading and trailing slash on the URI
    resource_uri = "/" + self.conn_id.to_s.gsub(/(^\/|\/$)/, '') + "/"
    self.passive_service = self.passive_dispatcher
    self.passive_service.remove_resource(resource_uri)
    self.passive_service.add_resource(resource_uri,
      'Proc'             => Proc.new { |cli, req| on_passive_request(cli, req) },
      'VirtualDirectory' => true
    )

    # Add a reference count to the handler
    self.passive_service.ref
  end

  def shutdown_passive_dispatcher
    if self.passive_service
      # Ensure that there is only one leading and trailing slash on the URI
      resource_uri = "/" + self.conn_id.to_s.gsub(/(^\/|\/$)/, '') + "/"
      self.passive_service.remove_resource(resource_uri) if self.passive_service

      self.passive_service.deref
      self.passive_service = nil
    end
    super
  end

  def on_passive_request(cli, req)

    begin

    resp = Rex::Proto::Http::Response.new(200, "OK")
    resp['Content-Type'] = 'application/octet-stream'
    resp['Connection']   = 'close'

    self.last_checkin = ::Time.now

    if req.method == 'GET'
      rpkt = send_queue.shift
      resp.body = rpkt || ''
      begin
        cli.send_response(resp)
      rescue ::Exception => e
        send_queue.unshift(rpkt) if rpkt
        elog("Exception sending a reply to the reader request #{cli.inspect}", error: e)
      end
    else
      resp.body = ""
      if req.body and req.body.length > 0
        packet = Packet.new(0)
        packet.add_raw(req.body)
        packet.parse_header!
        packet = decrypt_inbound_packet(packet)
        dispatch_inbound_packet(packet)
      end
      cli.send_response(resp)
    end

    rescue ::Exception => e
      elog("Exception handling request: #{cli.inspect} #{req.inspect}", error: e)
    end
  end

end

end; end; end
