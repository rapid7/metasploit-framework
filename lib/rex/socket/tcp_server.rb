require 'rex/socket'
require 'rex/socket/tcp'
require 'rex/io/stream_server'

###
#
# TcpServer
# ---------
#
# This class provides methods for interacting with a TCP server.  It
# implements the StreamServer IO interface.
#
#
###
class Rex::Socket::TcpServer < Rex::Socket
	include Rex::IO::StreamServer

	##
	#
	# Factory
	#
	##

	#
	# Creates the server using the supplied hash
	#
	def self.create(hash)
		self.create_param(Rex::Socket::Parameters.from_hash(hash))	
	end

	#
	# Wrapper around the base class' creation method that automatically sets
	# the parameter's protocol to TCP and sets the server flag to true
	#
	def self.create_param(param)
		param.proto  = 'tcp'
		param.server = true

		super(param)
	end

	##
	#
	# Class initialization
	#
	##

	##
	#
	# StreamServer mixin implementation
	#
	##

	#
	# Accepts a child connection
	#
	def accept(opts = {})
		Rex::Socket::Tcp.new(self.sock.accept[0])
	end

	#
	# Returns whether or not one or more client connections are pending
	# acceptance
	#
	def pending_client?(timeout = nil)
		timeout = timeout.to_i if (timeout)

		return (Rex::ThreadSafe.select([ poll_fd ], nil, nil, timeout) != nil)
	end
end
