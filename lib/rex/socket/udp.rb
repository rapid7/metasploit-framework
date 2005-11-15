require 'rex/socket'

###
#
# This class provides methods for interacting with a UDP socket.
#
###
module Rex::Socket::Udp

	include Rex::Socket

	##
	#
	# Factory
	#
	##

	#
	# Creates the client using the supplied hash.
	#
	def self.create(hash = {})
		self.create_param(Rex::Socket::Parameters.from_hash(hash))
	end

	#
	# Wrapper around the base socket class' creation method that automatically
	# sets the parameter's protocol to UDP.
	#
	def self.create_param(param)
		param.proto = 'udp'

		Rex::Socket.create_param(param)
	end

	##
	#
	# UDP connected state methods
	#
	##

	#
	# Write the supplied datagram to the connected UDP socket.
	#
	def write(gram)
		return syswrite(gram)
	end

	#
	# Read a datagram from the UDP socket.
	#
	def read(length = 65535)
		return sysread(length)
	end

	#alias send write
	#alias recv read

	##
	#
	# UDP non-connected state methods
	#
	##

	#
	# Sends a datagram to the supplied host:port with optional flags.
	#
	def sendto(gram, peerhost, peerport, flags = 0)
		return send(gram, flags, Rex::Socket.to_sockaddr(peerhost, peerport))
	end

	#
	# Receives a datagram and returns the data and host:port of the requestor
	# as [ data, host, port ].
	#
	def recvfrom(length = 65535)
		data, saddr    = super(length)
		af, host, port = Rex::Socket.from_sockaddr(saddr)

		return [ data, host, port ]
	end

end
