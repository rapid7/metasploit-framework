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

	def Generic.find_key(*crap)
		raise NotImplementedError, "We are lazy bums!", caller
	end

	def Generic.encode(buf, key)

		if !key.kind_of?(String)
			raise ArgumentError, "Key must be a string!", caller
		end

		len = key.length

		if len == 0
			raise ArgumentError, "Zero key length!", caller
		end

		if keysize != 0 && keysize != len
			raise ArgumentError, "Key length #{len}, expected #{keysize}", caller
		end

		encoded = ""
		pos     = 0

		while pos < buf.length
			encoded += (buf[pos] ^ key[pos % len]).chr
			pos += 1
		end

		return encoded

	end

	# maybe a bit a smaller of method name?
	def Generic.find_key_and_encode()
	end


end end end end # Generic/Xor/Encoding/Rex
