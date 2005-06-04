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
end

###
#
# TimeoutError
# ------------
#
# A timeout occurred.
#
###
class TimeoutError < Interrupt
	include Exception
end

###
#
# NotImplementedError
# -------------------
#
# The requested method is not implemented.
#
###
class NotImplementedError < ::NotImplementedError
	include Exception
end

###
#
# ArgumentError
# -------------
#
# An invalid argument was specified.
#
###
class ArgumentError < ::ArgumentError
	include Exception
end

end # Rex
