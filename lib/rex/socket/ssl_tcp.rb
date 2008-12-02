require 'rex/socket'

###
#
# This class provides methods for interacting with an SSL TCP client
# connection.
#
###
module Rex::Socket::SslTcp

begin
	@@loaded_openssl = false
	
	begin
		require 'openssl'
		@@loaded_openssl = true
	rescue ::Exception
	end
	

	include Rex::Socket::Tcp

	##
	#
	# Factory
	#
	##

	#
	# Creates an SSL TCP instance.
	#
	def self.create(hash)
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
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

	#
	# Initializes the SSL socket.
	#
	def initsock(params = nil)
		super

		# Build the SSL connection
		self.sslctx  = OpenSSL::SSL::SSLContext.new
		
		# Configure the SSL context
		# TODO: Allow the user to specify the verify mode and callback
		# Valid modes:
		#  VERIFY_CLIENT_ONCE
		#  VERIFY_FAIL_IF_NO_PEER_CERT 
		#  VERIFY_NONE
		#  VERIFY_PEER
		self.sslctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
		self.sslctx.options = OpenSSL::SSL::OP_ALL
		
		# Set the verification callback
		self.sslctx.verify_callback = Proc.new do |valid, store|
			self.peer_verified = valid
			true
		end
		
		# Tie the context to a socket
		self.sslsock = OpenSSL::SSL::SSLSocket.new(self, self.sslctx)
		
		# XXX - enabling this causes infinite recursion, so disable for now
		# self.sslsock.sync_close = true
		
		# Negotiate the connection
		self.sslsock.connect
	end

	##
	#
	# Stream mixin implementations
	#
	##

	#
	# Writes data over the SSL socket.
	#
	def write(buf, opts = {})
		return sslsock.write(buf)
	end

	#
	# Reads data from the SSL socket.
	#
	def read(length = nil, opts = {})
		length = 16384 unless length

		begin
			return sslsock.sysread(length)
		rescue EOFError, ::Errno::EPIPE
			return nil
		end
	end

	#
	# Closes the SSL socket.
	#
	def close
		sslsock.close
		super
	end

	# 
	# Ignore shutdown requests
	#
	def shutdown(how=0)
		# Calling shutdown() on an SSL socket can lead to bad things
		# Cause of http://metasploit.com/dev/trac/ticket/102
	end
	
	#
	# Access to peer cert
	#
	def peer_cert
		sslsock.peer_cert if sslsock
	end
	
	#
	# Access to peer cert chain
	#
	def peer_cert_chain
		sslsock.peer_cert_chain if sslsock
	end
	
	#
	# Access to the current cipher
	#
	def cipher
		sslsock.cipher if sslsock
	end



	attr_reader :peer_verified # :nodoc:
	attr_accessor :sslsock, :sslctx # :nodoc:
protected

	attr_writer :peer_verified # :nodoc:

rescue LoadError
end

	def type?
		return 'tcp-ssl'
	end

end
