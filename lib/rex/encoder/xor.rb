#!/usr/bin/ruby

module Rex
module Encoder

class Xor

	attr_accessor :raw, :encoded, :badchars, :opts, :key, :fkey

	# wrap that shit in a wanna be static class
	def self.encode(*args)
		self.new.encode(*args)
	end

	def encoder()
		self.class::EncoderKlass
	end

	def _unencoded_transform(data)
		data
	end

	def _encoded_transform(data)
		data
	end

	def encode(data, badchars = '', opts = { })
		self.raw      = data
		self.badchars = badchars
		self.opts     = opts

		# apply any transforms to the plaintext data
		data = _unencoded_transform(data)

		self.encoded, self.key, self.fkey = encoder().find_key_and_encode(data, badchars)

		# apply any transforms to the encoded data
		self.encoded = _encoded_transform(encoded)

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
