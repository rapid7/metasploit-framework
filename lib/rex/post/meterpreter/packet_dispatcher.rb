#!/usr/bin/env ruby

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
	def initialize(method, result)
		@method = method
		@result = result
	end

	def to_s
		"#{@method}: Operation failed: #{@result}"
	end

	# The method that failed.
	attr_reader :method

	# The error result that occurred, typically a windows error code.
	attr_reader :result
end

###
#
# Handles packet transmission, reception, and correlation,
# and processing
#
###
module PacketDispatcher

	PacketTimeout = 30

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

		if (raw)
			bytes = self.sock.write(raw)
		end

		return bytes
	end

	#
	# Sends a packet and waits for a timeout for the given time interval.
	#
	def send_request(packet, t = self.response_timeout)
		response = send_packet_wait_response(packet, t)

		if (response == nil)
			raise TimeoutError
		elsif (response.result != 0)
			e = RequestError.new(packet.method, response.result)

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
		if (send_packet(packet) <= 0)
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
		self.waiters = []

		# Spawn a new thread that monitors the socket
		self.dispatcher_thread = ::Thread.new do
			@pqueue = []
			@finish = false

			dthread = ::Thread.new do
				while (true)
					begin
						rv = Rex::ThreadSafe.select([ self.sock.fd ], nil, nil, 0.25)
						next if not rv
						packet = receive_packet
						@pqueue << packet if packet
					rescue ::Exception
						dlog("Exception caught in monitor_socket: #{$!}", 'meterpreter', LEV_1)
						@finish = true
						break
					end
				end
			end

			begin
			while(not @finish)
				if(@pqueue.empty?)
					select(nil, nil, nil, 0.10)
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

				@pqueue.unshift(*incomplete)

				if(@pqueue.length > 100)
					dlog("Backlog has grown to over 100 in monitor_socket, dropping older packets: #{@pqueue[0 .. 25].map{|x| x.inspect}.join(" - ")}", 'meterpreter', LEV_1)
					@pqueue = @pqueue[25 .. 100]
				end
			end
			rescue ::Exception => e
				dlog("Exception caught in monitor_socket dispatcher: #{e.class} #{e} #{e.backtrace}", 'meterpreter', LEV_1)
			ensure
				dthread.kill if dthread
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

	attr_accessor :dispatcher_thread # :nodoc:
	attr_accessor :waiters # :nodoc:
end

end; end; end

