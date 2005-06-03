require 'Rex/Socket'
require 'Rex/IO/Stream'

###
#
# Tcp
# ---
#
# This class provides methods for interacting with a TCP client connection.
#
###
class Rex::Socket::Tcp < Rex::Socket
	include Rex::IO::Stream

	##
	#
	# Factory
	#
	##

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

	def blocking=(tf)
		return tf # FIXME
	end

	def blocking
		return true # FIXME
	end

	def write(buf, opts = {})
		return sock.syswrite(buf)
	end

	def read(length = nil, opts = {})
		length = 16384 unless length

		begin
			return sock.sysread(length)
		rescue EOFError
			return nil
		end
	end

	def shutdown(how = SHUT_RDWR)
		return (sock.shutdown(how) == 0)
	end

	def has_read_data?(timeout = nil)
		timeout = timeout.to_i if (timeout)

		return (select([ poll_fd ], nil, nil, timeout) != nil)
	end

end
