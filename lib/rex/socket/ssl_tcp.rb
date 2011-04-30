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
		require 'openssl/nonblock'
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
	def self.create(hash = {})
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		hash['SSL'] = true
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

		version = :SSLv3
		if(params)
			case params.ssl_version
			when 'SSL2'
				version = :SSLv2
			when 'SSL23'
				version = :SSLv23				
			when 'TLS1'
				version = :TLSv1
			end
		end
		
		# Build the SSL connection
		self.sslctx  = OpenSSL::SSL::SSLContext.new(version)
		
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

		# Force a negotiation timeout
		begin
		Timeout.timeout(params.timeout) do 	
			if not self.sslsock.respond_to?(:connect_nonblock)
				self.sslsock.connect
			else
				begin
					self.sslsock.connect_nonblock
				rescue ::OpenSSL::SSL::ReadAgain, ::OpenSSL::SSL::WriteAgain
					select(nil, nil, nil, 0.10)
					retry
				end
			end
		end

		rescue ::Timeout::Error
			raise Rex::ConnectionTimeout.new(params.peerhost, params.peerport)
		end
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
		return sslsock.write(buf) if not self.sslsock.respond_to?(:write_nonblock)

		total_sent   = 0
		total_length = buf.length
		block_size   = 32768

		begin
			while( total_sent < total_length )
				s = Rex::ThreadSafe.select( nil, [ sslsock ], nil, 0.25 )
				if( s == nil || s[0] == nil )
					next
				end
				data = buf[total_sent, block_size]
				sent = sslsock.write_nonblock( data )
				if sent > 0
					total_sent += sent
				end
			end
		rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK, ::OpenSSL::SSL::ReadAgain, ::OpenSSL::SSL::WriteAgain
			# Sleep for a half a second, or until we can write again
			Rex::ThreadSafe.select( nil, [ sslsock ], nil, 0.5 )
			# Decrement the block size to handle full sendQs better
			block_size = 1024
			# Try to write the data again
			retry
		rescue ::IOError, ::Errno::EPIPE
			return nil if (fd.abortive_close == true)
		end
		total_sent
	end

	#
	# Reads data from the SSL socket.
	#
	def read(length = nil, opts = {})	
		if not self.sslsock.respond_to?(:read_nonblock)
			length = 16384 unless length
			begin
				return sslsock.sysread(length)
			rescue EOFError, ::Errno::EPIPE
				raise EOFError
			end
			return
		end
		
		begin
			while true 
				s = Rex::ThreadSafe.select( [ sslsock ], nil, nil, 0.10 )	
				if( s == nil || s[0] == nil )
					next
				end						
				buf = sslsock.read_nonblock( length ) 				
				return buf if buf
				raise ::EOFError
			end
		rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK, ::OpenSSL::SSL::ReadAgain, ::OpenSSL::SSL::WriteAgain
			# Sleep for a half a second, or until we can read again
			Rex::ThreadSafe.select( [ sslsock ], nil, nil, 0.5 )
			retry
		rescue ::IOError, ::Errno::EPIPE
			return nil if (fd.abortive_close == true)
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
