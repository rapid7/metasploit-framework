#!/usr/bin/ruby

require 'socket'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/PacketParser'

module Rex
module Post
module Meterpreter

###
#
# Client
# ------
#
# The logical meterpreter client class.  This class manages a single session
# with a meterpreter server instance.
#
###
class Client

	def initialize(sock)
		self.sock   = sock
		self.parser = PacketParser.new

		monitor_socket
	end

	def brand(klass)
		klass = klass.dup
		klass.client = self
		return klass
	end

	#
	# Packet transmission/reception
	#

	def dispatch_inbound_packet(packet)
		printf "Got packet with rid #{packet.rid}, method #{packet.method}\n"
	end

	def monitor_socket

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

	def send_packet(packet)
		bytes = 0
		raw   = packet.to_r

		if (raw)
			bytes = self.sock.write(raw)
		end	

		return bytes
	end

	def receive_packet
		return parser.recv(self.sock)
	end

	protected
	attr_accessor :sock, :parser
end

end; end; end
