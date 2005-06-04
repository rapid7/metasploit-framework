#!/usr/bin/ruby

module Rex

###
#
# Exception
# ---------
#
# Base mixin for all exceptions that can be thrown from inside Rex.
#
###
module Exception
	def to_s
		return "An unknown exception occurred."
	end
end

###
#
# TimeoutError
#
###
class TimeoutError < Interrupt
	include Exception

	def to_s
		return "Operation timed out."
	end
end

###
#
# NotImplementedError
#
###
class NotImplementedError < ::NotImplementedError
	include Exception

	def to_s
		return "The requested method is not implemented."
	end
end

###
#
# ArgumentError
#
###
class ArgumentError < ::ArgumentError
	include Exception

	def to_s
		return "An invalid argument was specified."
	end
end

#####
#####
##
#
# Socket exceptions
#
##
#####
#####

###
#
# SocketError
#
###
module SocketError
	include Exception

	def to_s
		return "A socket error occurred."
	end
end

###
# 
# HostCommunicationError
# ----------------------
#
# Implements helper methods for errors that occurred when communicating to a
# host.
#
###
module HostCommunicationError
	def initialize(addr = nil, port = nil)
		self.host = addr
		self.port = port
	end

	def addr_to_s
		if (host && port)
			return " (#{host}:#{port})"
		end

		return ""
	end

	attr_accessor :host, :port
end

###
#
# ConnectionRefused
#
###
class ConnectionRefused < ::IOError
	include SocketError
	include HostCommunicationError

	def to_s
		return "The connection was refused by the remote host#{addr_to_s}."
	end
end

###
#
# ConnectionTimeout 
#
###
class ConnectionTimeout < ::Interrupt
	include SocketError
	include HostCommunicationError

	def to_s
		return "The connection timed out#{addr_to_s}."
	end
end

class AddressInUse < ::RuntimeError
	include SocketError
	include HostCommunicationError

	def to_s
		return "The address is already in use#{addr_to_s}."
	end
end

end # Rex
