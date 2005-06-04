require 'Msf/Core'

module Msf

###
#
# Error
# -----
#
# Mixin that should be included in all exceptions that can be thrown from the
# framework so that they can be universally caught.  Framework exceptions
# automatically extended Rex exceptions
#
###
module Exception
	include Rex::Exception
end

###
#
# EncodingError
# -------------
#
###
class EncodingError < RuntimeError
	include Exception
end

###
#
# NoKeyError
# ----------
#
# Thrown when an encoder fails to find a viable encoding key.
#
###
class NoKeyError < EncodingError
end

###
#
# BadcharError
# ------------
#
# Thrown when an encoder fails to encode a buffer due to a bad character.
#
###
class BadcharError < EncodingError
	def initialize(buf, index, stub_size, char)
		@buf       = buf
		@index     = index
		@stub_size = stub_size
		@char      = char
	end

	attr_reader :buf, :index, :stub_size, :char
end

###
#
# OptionValidateError
# ------------------
#
# This exception is thrown when one or more options failed
# to pass data store validation.  The list of option names
# can be obtained through the options attribute.
#
###
class OptionValidateError < ArgumentError
	include Exception

	def initialize(options)
		@options = options
	end

	attr_reader :options
end

end
