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
# Handles packet transmission, reception, and correlation
#
###
module PacketDispatcher
	def dispatch_inbound_packet(packet)
		puts "Inbound packet: rid=#{packet.rid} method=#{packet.method}\n"

		# If the packet is a response, try to notify any potential
		# waiters
		if (packet.response?)
			if (notify_response_waiter(packet))
				return true
			end
		end
	end

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

	def monitor_socket
		self.waiters = []

		# Spawn a new thread that monitors the socket
		thr = Thread.new {
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

	def send_request(packet, t = Client.default_timeout)
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

	def receive_packet
		return parser.recv(self.sock)
	end

	protected
	attr_accessor :waiters
end

end; end; end
