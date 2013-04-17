# -*- coding: binary -*-
require 'rex/socket'
require 'rex/io/stream'

###
#
# This class provides methods for interacting with a TCP client connection.
#
###
module Rex::Socket::Tcp

	include Rex::Socket
	include Rex::IO::Stream

	##
	#
	# Factory
	#
	##

	#
	# Creates the client using the supplied hash.
	#
	# @see create_param
	# @see Rex::Socket::Parameters.from_hash
	def self.create(hash = {})
		hash['Proto'] = 'tcp'
		self.create_param(Rex::Socket::Parameters.from_hash(hash))
	end

	#
	# Wrapper around the base socket class' creation method that automatically
	# sets the parameter's protocol to TCP.
	#
	def self.create_param(param)
		param.proto = 'tcp'
		Rex::Socket.create_param(param)
	end

	##
	#
	# Stream mixin implementations
	#
	##

	#
	# Calls shutdown on the TCP connection.
	#
	def shutdown(how = ::Socket::SHUT_RDWR)
		begin
			return (super(how) == 0)
		rescue ::Exception
		end
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

	# returns socket type
	def type?
		return 'tcp'
	end

end
