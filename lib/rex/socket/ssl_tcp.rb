require 'openssl'
require 'rex/socket'
require 'rex/io/stream'

###
#
# SslTcp
# ---
#
# This class provides methods for interacting with an SSL TCP client connection.
#
###
class Rex::Socket::SslTcp < Rex::Socket::Tcp

	##
	#
	# Factory
	#
	##

	#
	# Set the SSL flag to true and call the base class's create_param routine.
	#
	def self.create_param(param)
		param.ssl = true

		super(param)
	end

	##
	#
	# Class initialization
	#
	##
	
	def initialize(sock, params = nil)
		super

		# Build the SSL connection
		self.sslctx  = OpenSSL::SSL::SSLContext.new
		self.sslsock = OpenSSL::SSL::SSLSocket.new(sock, self.sslctx)
		self.sslsock.sync_close = true
		self.sslsock.connect
	end

	##
	#
	# Stream mixin implementations
	#
	##

	def write(buf, opts = {})
		return sslsock.write(buf)
	end

	def read(length = nil, opts = {})
		length = 16384 unless length

		begin
			return sslsock.read(length)
		rescue EOFError
			return nil
		end
	end

	def shutdown(how = SHUT_RDWR)
		return (sock.shutdown(how) == 0)
	end

	def close
		sslsock.close
		sock.close
	end

	def has_read_data?(timeout = nil)
		timeout = timeout.to_i if (timeout)

		return (select([ poll_fd ], nil, nil, timeout) != nil)
	end

protected

	attr_accessor :sslsock, :sslctx

end
