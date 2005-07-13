require 'msf/core'

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

	def to_s
		"A framework exception occurred."
	end
end

###
#
# OptionValidateError
# -------------------
#
# This exception is thrown when one or more options failed
# to pass data store validation.  The list of option names
# can be obtained through the options attribute.
#
###
class OptionValidateError < ArgumentError
	include Exception

	def initialize(options = [])
		@options = options
	end

	def to_s
		"The following options failed to validate: #{options.join(', ')}."
	end

	attr_reader :options
end

class ValidationError < ArgumentError
	include Exception

	def to_s
		"One or more requirements could not be validated."
	end
end

##
#
# Encoding exceptions
#
##

class EncodingError < RuntimeError
	include Exception

	def to_s
		"A encoding exception occurred."
	end
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
	def to_s
		"A valid encoding key could not be found."
	end
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
	def initialize(buf = nil, index = nil, stub_size = nil, char = nil)
		@buf       = buf
		@index     = index
		@stub_size = stub_size
		@char      = char
	end

	def to_s
		"Encoding failed due to a bad character (index=#{index}, char=#{sprintf("0x%.2x", char)})"
	end

	attr_reader :buf, :index, :stub_size, :char
end

class NoEncodersSucceededError < EncodingError

	def to_s
		"No encoders encoded the buffer successfully."
	end
end

##
#
# Exploit exceptions
#
##

module ExploitError
	include Exception

	def to_s
		"An exploitation error occurred."
	end
end

class MissingTargetError < ArgumentError
	include ExploitError

	def to_s
		"A target has not been selected."
	end
end

class MissingPayloadError < ArgumentError
	include ExploitError

	def to_s
		"A payload has not been selected."
	end
end

class IncompatiblePayloadError < ArgumentError
	include ExploitError

	def initialize(pname = nil)
		@pname = pname
	end

	def to_s
		"#{pname} is not a compatible payload."
	end

	attr_reader :pname
end

##
#
# NOP exceptions
#
##

module NopError
	include Exception

	def to_s
		"A NOP generator error occurred."
	end
end

class NoNopsSucceededError < RuntimeError
	include NopError

	def to_s
		"No NOP generators succeeded."
	end
end


end
