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
		"An unknown exception occurred."
	end
end

class TimeoutError < Interrupt
	include Exception

	def to_s
		"Operation timed out."
	end
end

class NotImplementedError < ::NotImplementedError
	include Exception

	def to_s
		"The requested method is not implemented."
	end
end

class RuntimeError < ::RuntimeError
	include Exception

	def to_s
		"A runtime error occurred."
	end
end

class ArgumentError < ::ArgumentError
	include Exception

	def to_s
		"An invalid argument was specified."
	end
end

class ArgumentParseError < ::ArgumentError
	include Exception

	def to_s
		"The argument could not be parsed correctly."
	end
end

class AmbiguousArgumentError < ::RuntimeError
	include Exception

	def initialize(name)
		@name = name
	end

	def to_s
		"The name #{@name} is ambiguous."
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

module SocketError
	include Exception

	def to_s
		"A socket error occurred."
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
		(host && port) ? " (#{host}:#{port})" : ""
	end

	attr_accessor :host, :port
end

class ConnectionRefused < ::IOError
	include SocketError
	include HostCommunicationError

	def to_s
		"The connection was refused by the remote host#{addr_to_s}."
	end
end

class ConnectionTimeout < ::Interrupt
	include SocketError
	include HostCommunicationError

	def to_s
		"The connection timed out#{addr_to_s}."
	end
end

class AddressInUse < ::RuntimeError
	include SocketError
	include HostCommunicationError

	def to_s
		"The address is already in use#{addr_to_s}."
	end
end

class UnsupportedProtocol < ::ArgumentError
	include SocketError

	def initialize(proto = nil)
		self.proto = proto
	end

	def to_s
		"The protocol #{proto} is not supported."	
	end

	attr_accessor :proto
end

end # Rex
