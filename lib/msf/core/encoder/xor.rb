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
		return Rex::Encoding::Xor::Dword.encode(block, [ state.key ].pack(state.decoder_key_pack))[0]
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
		badchars.each_byte { |badchar|
			
			buf.each_byte { |byte|
				bad_keys[byte_idx % decoder_key_size][byte ^ badchar] = true
				
				byte_idx += 1
			}
			
			# Assume our key itself is placed w/o encoding
			0.upto(decoder_key_size-1) { |i|
				bad_keys[i][badchar] = true
			}
		}
		
		return bad_keys
	end
	
	# Added for test purposes, remove once we resolve encoding issues...
	def find_key_verify(buf, key_bytes, badchars)
		ekey = key_bytes_to_buffer(key_bytes)

		out = ''
		idx = 0
		while (idx < buf.length)
			0.upto(ekey.length-1) do |i|
				break if ! buf[idx+i]
				out << (buf[idx+i]^ekey[i]).chr
			end
			
			idx += ekey.length
		end
		
		badchars.each do |c|
			return false if out.index(c)
		end
		
		true
	end

	
end
