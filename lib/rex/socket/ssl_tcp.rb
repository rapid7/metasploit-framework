require 'rex/socket'

###
#
# This class provides methods for interacting with an SSL TCP client
# connection.
#
###
module Rex::Socket::SslTcp

begin
	require 'openssl'

	include Rex::Socket::Tcp

	##
	#
	# Factory
	#
	##

	def self.create(hash)
		self.create_param(Rex::Socket::Parameters.from_hash(hash))
	end

	#
	# Set the SSL flag to true and call the base class's create_param routine.
	#
	def self.create_param(param)
		param.ssl   = true

		Rex::Socket::Tcp.create_param(param)
	end

	##
	#
	# Class initialization
	#
	##
	
	def initsock(params = nil)
		super

		# Build the SSL connection
		self.sslctx  = OpenSSL::SSL::SSLContext.new
		self.sslsock = OpenSSL::SSL::SSLSocket.new(self, self.sslctx)
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

	def close
		sslsock.close
		super
	end

protected

	attr_accessor :sslsock, :sslctx

rescue LoadError
end

end
