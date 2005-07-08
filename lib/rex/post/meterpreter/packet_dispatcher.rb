#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/PacketResponseWaiter'

module Rex
module Post
module Meterpreter

###
#
# PacketDispatcher
# ----------------
#
# Handles packet transmission, reception, and correlation,
# and processing
#
###
module PacketDispatcher

	##
	#
	# Transmission
	#
	##

	# Sends a packet without waiting for a response
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

	# Sends a packet and waits for a timeout for the given time interval
	def send_request(packet, t = self.response_timeout)
		response = send_packet_wait_response(packet, t)

		if (response == nil)
			raise RuntimeError, packet.method + ": No response was received.", caller
		elsif (response.result != 0)
			raise RuntimeError, packet.method + ": Operation failed: #{response.result}", caller
		end

		return response
	end

	# Transmits a packet and waits for a response
	def send_packet_wait_response(packet, t)
		# First, add the waiter association for the supplied packet
		waiter = add_response_waiter(packet)

		# Transmit the packet
		if (send_packet(packet) <= 0)
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

	# Monitors the PacketDispatcher's sock for data in its own
	# thread context and parsers all inbound packets
	def monitor_socket
		self.waiters = []

		# Spawn a new thread that monitors the socket
		thr = ::Thread.new {
			while (true)
				rv = select([ self.sock ], nil, nil, 2)

				begin
					packet = receive_packet
				rescue EOFError
					puts "EOF reached on socket\n"
					break
				end

				if (packet)
					dispatch_inbound_packet(packet)
				end
			end
		}
	end

	# Parses data from the dispatcher's sock and returns a Packet context
	# once a full packet has been received
	def receive_packet
		return parser.recv(self.sock)
	end


	##
	#
	# Waiter registration
	#
	##

	# Adds a waiter association with the supplied request packet
	def add_response_waiter(request, completion_routine = nil, completion_param = nil)
		waiter = PacketResponseWaiter.new(request.rid, completion_routine, completion_param)

		self.waiters << waiter

		return waiter
	end

	# Notifies a whomever is waiting for a the supplied response,
	# if anyone
	def notify_response_waiter(response)
		self.waiters.each() { |waiter|
			if (waiter.waiting_for?(response))
				waiter.notify(response)

				remove_response_waiter(waiter)

				break
			end
		}
	end

	# Removes a waiter from the list of waiters
	def remove_response_waiter(waiter)
		self.waiters.delete(waiter)
	end

	##
	#
	# Dispatching
	#
	##

	def initialize_inbound_handlers
		@inbound_handlers = []
	end

	# Dispatches and processes an inbound packet.  If the packet is a
	# response that has an associated waiter, the waiter is notified.
	# Otherwise, the packet is passed onto any registered dispatch
	# handlers until one returns success.
	def dispatch_inbound_packet(packet, client = nil)
		handled = false

		# If no client context was provided, return self as PacketDispatcher
		# is a mixin for the Client instance
		if (client == nil)
			client = self
		end

		#puts "Inbound packet: rid=#{packet.rid} method=#{packet.method}\n"

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

			if (!resp)
				handled = handler.request_handler(client, packet)
			else
				handled = handler.response_handler(client, packet)
			end

			if (handled)
				break
			end
		}

		return handled
	end

	# Registers an inbound packet handler that implements the
	# InboundPacketHandler interface.
	def register_inbound_handler(handler)
		@inbound_handlers << handler
	end

	# Deregisters a previously registered inbound packet handler
	def deregister_inbound_handler(handler)
		@inbound_handlers.delete(handler)
	end

protected

	attr_accessor :waiters
end

end; end; end
