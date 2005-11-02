require 'msf/core'

###
#
# This class provides basic XOR encoding of buffers.
#
###
class Msf::Encoder::Xor < Msf::Encoder

	def encode_block(state, block)
		return Rex::Encoding::Xor::Dword.encode(block, [ state.key ].pack(state.decoder_key_pack))[0]
	end

	def find_bad_keys(buf, badchars)
		bad_keys = [ {}, {}, {}, {} ]
		byte_idx = 0

		# Scan through all the badchars and build out the bad_keys array
		# based on the XOR'd combinations that can occur at certain bytes
		# to produce bad characters
		badchars.each_byte { |badchar|
			buf.each_byte { |byte|
				bad_keys[byte_idx % decoder_key_size][byte ^ badchar] = true
			
				byte_idx += 1
			}
		}

		return bad_keys
	end

	
end
