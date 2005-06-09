#!/usr/bin/ruby

module Rex
module Encoder

class Xor

	attr_accessor :raw, :encoded, :badchars, :opts, :key

	# wrap that shit in a wanna be static class
	def self.encode(*args)
		self.new.encode(*args)
	end

	def encoder()
		self.class::EncoderKlass
	end

	def encode(data, badchars = '', opts = { })
		self.raw      = data
		self.badchars = badchars
		self.opts     = opts

		self.encoded, self.key = encoder().find_key_and_encode(data, badchars)
		return _prepend() + encoded + _append()
	end

	protected
	def _prepend()
		""
	end

	def _append()
		""
	end

end

end end
