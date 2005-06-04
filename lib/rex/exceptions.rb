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
# ConnectionRefused
#
###
class ConnectionRefused < ::IOError
	include SocketError

	def to_s
		return "The connection was refused by the remote host."
	end
end

###
#
# ConnectionTimeout 
#
###
class ConnectionTimeout < ::Interrupt
	include SocketError

	def to_s
		return "The connection timed out."
	end
end

end # Rex
