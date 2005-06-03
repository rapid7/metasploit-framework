require 'Rex/Socket'
require 'Rex/IO/Stream'

class Rex::Socket::Tcp < Rex::Socket
	include Rex::IO::Stream

	##
	#
	# Class initialization
	#
	##
	
	def initialize(sock)
		super
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

	def shutdown(how = SW_BOTH)
		return sock.shutdown(how)
	end

	def close
		sock.close
	end

	def poll_read(timeout = nil)
		return select([ poll_fd ], nil, nil, timeout)
	end

	def poll_fd
		return sock
	end
	
end
