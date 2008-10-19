require 'msf/core'

###
#
# This class provides basic XOR encoding of buffers.
#
###
class Msf::Encoder::Xor < Msf::Encoder

	#
	# Encodes a block using the XOR encoder from the Rex library.
	#
	def encode_block(state, block)
		Rex::Encoding::Xor::Dword.encode(block, [ state.key ].pack(state.decoder_key_pack))[0]
	end

	#
	# Finds keys that are incompatible with the supplied bad character list.
	#
	def find_bad_keys(buf, badchars)
		bad_keys = [ {}, {}, {}, {} ]
		byte_idx = 0

		# Scan through all the badchars and build out the bad_keys array
		# based on the XOR'd combinations that can occur at certain bytes
		# to produce bad characters
		buf.each_byte { |byte|
			badchars.each_byte { |badchar|
				bad_keys[byte_idx % decoder_key_size][byte ^ badchar] = true
			}
			byte_idx += 1
		}

		badchars.each_byte { |badchar|
			0.upto(decoder_key_size-1) { |i|
				bad_keys[i][badchar] = true
			}
		}
		
		return bad_keys
	end
	
end