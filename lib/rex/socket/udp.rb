require 'Rex/Socket'

###
#
# Udp
# ---
#
# This class provides methods for interacting with a UDP socket.
#
###
class Rex::Socket::Udp < Rex::Socket

	##
	#
	# Factory
	#
	##

	#
	# Wrapper around the base socket class' creation method that automatically
	# sets the parameter's protocol to UDP
	#
	def self.create_param(param)
		param.proto = 'udp'

		super(param)
	end

	##
	#
	# UDP connected state methods
	#
	##

	#
	# Write the supplied datagram to the connected UDP socket
	#
	def write(gram)
		return sock.write(gram)
	end

	#
	# Read a datagram from the UDP socket
	#
	def read(length = 65535)
		return sock.read(length)
	end

	#alias send write
	#alias recv read

	##
	#
	# UDP non-connected state methods
	#
	##

	#
	# Sends a datagram to the supplied host:port with optional flags
	#
	def sendto(gram, peerhost, peerport, flags = 0)
		return sock.send(gram, flags, Rex::Socket.to_sockaddr(peerhost, peerport))
	end

	#
	# Receives a datagram and returns the data and host:port of the requestor
	# as [ data, host, port ]
	#
	def recvfrom(length = 65535)
		data, saddr    = sock.recvfrom(length)
		af, host, port = Rex::Socket.from_sockaddr(saddr)

		return [ data, host, port ]
	end

	#
	# Checks for whether or not any datagrams are pending read
	#
	def has_read_data?(timeout = nil)
		timeout = timeout.to_i if (timeout)

		return (select([ poll_fd ], nil, nil, timeout) != nil)
	end

end
