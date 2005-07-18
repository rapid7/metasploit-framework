require 'rex/socket'
require 'rex/io/stream'

###
#
# Tcp
# ---
#
# This class provides methods for interacting with a TCP client connection.
#
###
class Rex::Socket::Tcp < Rex::Socket
	
	SHUT_RDWR = 2
	SHUT_WR   = 1
	SHUT_RD   = 0

	include Rex::IO::Stream

	##
	#
	# Factory
	#
	##

	#
	# Creates the client using the supplied hash
	#
	def self.create(hash)
		self.create_param(Rex::Socket::Parameters.from_hash(hash))
	end

	#
	# Wrapper around the base socket class' creation method that automatically
	# sets the parameter's protocol to TCP
	#
	def self.create_param(param)
		param.proto = 'tcp'

		super(param)
	end

	##
	#
	# Stream mixin implementations
	#
	##

	#
	# Writes to the TCP connection.
	#
	def write(buf, opts = {})
		return sock.syswrite(buf)
	end

	#
	# Reads from the TCP connection and raises EOFError if there is no data
	# left.
	#
	def read(length = nil, opts = {})
		length = 16384 unless length

		return sock.sysread(length)
	end

	#
	# Calls shutdown on the TCP connection.
	#
	def shutdown(how = SHUT_RDWR)
		begin
			return (sock.shutdown(how) == 0)
		rescue Errno::ENOTCONN
		end
	end

	#
	# Checks to see if the connection has read data.
	#
	def has_read_data?(timeout = nil)
		timeout = timeout.to_i if (timeout)
	
		return (Rex::ThreadSafe.select([ poll_fd ], nil, nil, timeout) != nil)
	end

	#
	# Closes the connection.
	#
	def close
		self.sock.close if (self.sock)
	end

	#
	# Returns the file descriptor to use with calls to select.
	#
	def poll_fd
		return self.sock
	end

	#
	# Returns peer information (host + port) in host:port format.
	#
	def peerinfo
		if (pi = getpeername)
			return pi[1] + ':' + pi[2].to_s
		end
	end

	#
	# Returns local information (host + port) in host:port format.
	#
	def localinfo
		if (pi = getlocalname)
			return pi[1] + ':' + pi[2].to_s
		end
	end

end
