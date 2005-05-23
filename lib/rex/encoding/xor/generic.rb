#!/usr/bin/ruby

module Rex
module Encoding
module Xor

class Generic

	def Generic.keysize
		# special case:
		# 0 means we encode based on the length of the key
		# we don't enforce any perticular key length
		return 0
	end

	def Generic.encode(buf, key)

		if !key.kind_of?(String)
			raise ArgumentError, "Key must be a string!", caller
		end

		len  = key.length

		if keysize != 0 && keysize != len
			raise ArgumentError, "Key length #{len}, expected #{keysize}", caller
		end

		encoded = ""
		pos     = 0

		while pos < buf.length
			encoded += (buf[pos] ^ key[pos % len]).chr
		end

		return encoded

	end


end end end end # Generic/Xor/Encoding/Rex
