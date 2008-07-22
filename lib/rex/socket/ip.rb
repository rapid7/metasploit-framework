require 'rex/socket'

###
#
# This class provides methods for interacting with a UDP socket.
#
###
module Rex::Socket::Ip

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
		param.proto = 'ip'

		Rex::Socket.create_param(param)
	end

	##
	#
	# IP connected state methods
	#
	##

	#
	# Write the supplied datagram to the connected IP socket.
	#
	def write(gram)
		raise RuntimeError, "IP sockets must use sendto(), not write()"
	end

	#
	# Another alias for write
	#
	def put(gram)
		return write(gram)
	end

	#
	# Read a datagram from the UDP socket.
	#
	def read(length = 65535)
		raise RuntimeError, "IP sockets must use recvfrom(), not read()"
	end

	#
	# Read a datagram from the UDP socket with a timeout
	#
	def timed_read(length = 65535, timeout=def_read_timeout)
		begin
			if ((rv = Kernel.select([ fd ], nil, nil, timeout)) and
			    (rv[0]) and (rv[0][0] == fd)
			   )
					return read(length)
			else
				return ''
			end
		rescue Exception
			return ''
		end	
	end


	##
	#
	# IP non-connected state methods
	#
	##

	#
	# Sends a datagram to the supplied host:port with optional flags.
	#
	def sendto(gram, peerhost, flags = 0)
		dest = ::Socket.pack_sockaddr_in(1024, peerhost)
		send(gram, flags, dest)
	end

	#
	# Receives a datagram and returns the data and host of the requestor
	# as [ data, host ].
	#
	def recvfrom(length = 65535, timeout=def_read_timeout)
		begin
			if ((rv = Kernel.select([ fd ], nil, nil, timeout)) and
			    (rv[0]) and (rv[0][0] == fd)
			   )
					data, saddr    = super(length)
					af, host       = Rex::Socket.from_sockaddr(saddr)

					return [ data, host ]
			else
				return [ '', nil ]
			end
		rescue Exception
			return [ '', nil ]
		end
	end
	
	#
	# Calls recvfrom and only returns the data
	#
	def get(timeout=nil)
		data, saddr = recvfrom(65535, timeout)
		return data
	end
	
	#
	# The default number of seconds to wait for a read operation to timeout.
	#
	def def_read_timeout
		10
	end	

	def type?
		return 'ip'
	end

end
