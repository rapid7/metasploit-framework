#!/usr/bin/ruby

require 'Rex/Encoding/Xor/Generic'

#
# Routine for xor encoding a buffer by a 2-byte (intel word) key.  The perl
# version used to pad this buffer out to a 2-byte boundary, but I can't think
# of a good reason to do that anymore, so this doesn't.
#

module Rex
module Encoding
module Xor

class DWordAdditive < Generic

	def DWordAdditive.keysize
		4
	end

	def DWordAdditive._packspec
		'V'
	end

	def DWordAdditive.find_key
		raise NotImplementError, "I suck!", caller
	end

	def DWordAdditive.pack_key(key)
		return [ key ].pack(_packspec)
	end
	def DWordAdditive.unpack_key(key)
		return key.unpack(_packspec)[0]
	end

	# hook in the key mutation routine of encode for the additive feedback
	def DWordAdditive._encode_mutate_key(buf, key, pos, len)
		if (pos + 1) % len == 0
			# add the last len bytes (in this case 4) with the key,
			# dropping off any overflow
			key = pack_key(
			  unpack_key(key) + unpack_key(buf[-len, len]) &
			    (1 << (len << 3)) - 1
			)
			puts "mutated!"
		end
 
		return key
	end

end end end end # DWordAdditive/Xor/Encoding/Rex
