require 'Rex/Socket'
require 'Rex/Socket/Tcp'
require 'Rex/IO/StreamServer'

class Rex::Socket::TcpServer < Rex::Socket
	include Rex::IO::StreamServer

	##
	#
	# Factory
	#
	##

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
	# Since the Comm will take care of initiating the listener, we just return
	# true here to indicate that we're cool.
	#
	def listen(params, opts = {})
		return true	
	end

	#
	# Accepts a child connection
	#
	def accept(opts = {})
		return Rex::Socket::Tcp.new(sock.accept[0])
	end

	#
	# Returns whether or not one or more client connections are pending
	# acceptance
	#
	def pending_client?(timeout = nil)
		timeout = timeout.to_i if (timeout)

		return (select([ poll_fd ], nil, nil, timeout) != nil)
	end
end
