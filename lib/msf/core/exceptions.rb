module Msf

class EncodingException < RuntimeError
end

###
#
# NoKeyException
# --------------
#
# Thrown when an encoder fails to find a viable encoding key.
#
###
class NoKeyException < EncodingException
end

###
#
# BadcharException
# ----------------
#
# Thrown when an encoder fails to encode a buffer due to a bad character.
#
###
class BadcharException < EncodingException
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
# MissingOptionError
# ------------------
#
# This exception is thrown when one or more options failed
# to pass data store validation.  The list of option names
# can be obtained through the options attribute.
#
###
class OptionValidateError < ArgumentError
	def initialize(options)
		@options = options
	end

	attr_reader :options
end

end
