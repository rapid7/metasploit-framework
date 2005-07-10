require 'msf/core'

module Msf

###
#
# EncoderState
# ------------
#
# This class is used to track the state of a single encoding operation
# from start to finish.
#
###
class EncoderState

	def initialize(key = nil)
		reset(key)
	end

	# Reset the encoder state
	def reset(key = nil)
		init_key(key)

		self.encoded  = ''
	end

	# Set the initial encoding key
	def init_key(key)
		self.key      = key
		self.orig_key = key
	end

	attr_accessor :key
	attr_accessor :orig_key
	attr_accessor :encoded
	attr_accessor :context
	attr_accessor :badchars
	attr_accessor :buf

	# Decoder settings
	attr_accessor :decoder_key_offset, :decoder_key_size, :decoder_key_pack

end

###
#
# Encoder
# -------
#
# This class is the base class that all encoders inherit from.
#
###
class Encoder < Module

	def initialize(info)
		super(info)
	end

	#
	# Encoder information accessors that can be overriden
	# by derived classes
	#
	
	def type
		return MODULE_ENCODER
	end

	#
	# Returns the decoder stub to use based on the supplied length
	#
	def decoder_stub(state)
		return module_info['Decoder']['Stub']
	end

	def decoder_key_offset
		return module_info['Decoder']['KeyOffset']
	end

	def decoder_key_size
		return module_info['Decoder']['KeySize']
	end

	def decoder_block_size
		return module_info['Decoder']['BlockSize']
	end

	def decoder_key_pack
		return module_info['Decoder']['KeyPack'] || 'V'
	end

	#
	# Encoding
	#

	def encode(buf, badchars, state = nil)
		# Initialize an empty set of bad characters
		badchars = '' if (!badchars)

		# Initialize the encoding state and key as necessary
		if (state == nil)
			state = EncoderState.new
		end

		# Prepend data to the buffer as necessary
		buf = prepend_buf + buf

		# If this encoder is key-based and we don't already have a key, find one
		if ((decoder_key_size) and
		    (state.key == nil))
			# Find a key that doesn't contain and wont generate any bad
			# characters
			state.init_key(find_key(buf, badchars))

			if (state.key == nil)
				raise NoKeyError, "A key could not be found for the #{self.name} encoder.", caller
			end
		end

		# Update the state with default decoder information
		state.decoder_key_offset = decoder_key_offset
		state.decoder_key_size   = decoder_key_size
		state.decoder_key_pack   = decoder_key_pack

		# Save the buffer in the encoding state
		state.badchars = badchars
		state.buf      = buf

		# Call encode_begin to do any encoder specific pre-processing
		encode_begin(state)

		# Perform the actual encoding operation with the determined state
		do_encode(buf, badchars, state)

		# Call encoded_end to do any encoder specific post-processing
		encode_end(state)

		# Return the encoded buffer to the caller
		return state.encoded
	end

	def do_encode(buf, badchars, state)
		# Copy the decoder stub since we may need to modify it
		stub = decoder_stub(state).dup

		if (state.key != nil)
			# Substitute the decoder key in the copy of the decoder stub with the
			# one that we found
			stub[state.decoder_key_offset,state.decoder_key_size] = [ state.key.to_i ].pack(state.decoder_key_pack)
		end
		
		# Walk the buffer encoding each block along the way
		offset = 0

		while (offset < buf.length)
			block = buf[offset, decoder_block_size]

			state.encoded += encode_block(state, 
					block + ("\x00" * (decoder_block_size - block.length)))
		     
			offset += decoder_block_size
		end
		
		# Prefix the decoder stub to the encoded buffer
		state.encoded = stub + state.encoded

		# Last but not least, do one last badchar pass to see if the stub +
		# encoded payload leads to any bad char issues...
		if ((badchar_idx = has_badchars?(state.encoded, badchars)) != nil)
			raise BadcharError.new(state.encoded, badchar_idx, stub.length, badchars[badchar_idx]), 
					"The #{self.name} encoder failed to encode without bad characters.", 
					caller
		end

		return true
	end

	#
	# Buffer management
	#
	
	def prepend_buf
		return ''
	end

	#
	# Pre-processing, post-processing, and block encoding stubs
	#

	def encode_begin(state)
		return nil
	end

	def encode_end(state)
		return nil
	end

	def encode_block(state, block)
		return block
	end

protected

	def find_key(buf, badchars)
		key_bytes = [ ]
		cur_key   = [ ]
		bad_keys  = find_bad_keys(buf, badchars)
		found     = false

		# Keep chugging until we find something...right
		while (!found)
			# Scan each byte position
			0.upto(decoder_key_size - 1) { |index|
				cur_key[index] = rand(255)

				# Scan all 255 bytes (wrapping around as necessary)
				for cur_char in (cur_key[index] .. (cur_key[index] + 255))
					cur_char = (cur_char % 255) + 1

					# If this is a known bad character at this location in the
					# key or it doesn't pass the bad character check...
					if (((bad_keys != nil) and
					     (bad_keys[index][cur_char] == true)) or
					    (badchars.index(cur_char) != nil))
						next
					end

					key_bytes[index] = cur_char
				end
			}

			# Assume that we're going to rock this shit...
			found = true

			# Scan each byte and see what we've got going on to make sure
			# no funny business is happening
			key_bytes.each { |byte|
				if (badchars.index(byte) != nil)
					found = false
				end
			}
		end

		# Do we have all the key bytes accounted for?
		if (key_bytes.length != decoder_key_size)
			return nil
		end

		return key_bytes_to_integer(key_bytes)
	end

	def find_bad_keys
		return [ {}, {}, {}, {} ]
	end

	def has_badchars?(buf, badchars)
		badchars.each_byte { |badchar|
			idx = buf.index(badchar)

			if (idx != nil)
				return idx
			end	
		}

		return nil
	end

	# Convert individual key bytes into a single integer based on the 
	# decoder's key size and packing requirements
	def key_bytes_to_integer(key_bytes)
		return key_bytes.pack('C' + decoder_key_size.to_s).unpack(decoder_key_pack)[0]
	end

	# Convert an integer into the individual key bytes based on the 
	# decoder's key size and packing requirements
	def integer_to_key_bytes(integer)
		return [ integer.to_i ].pack(decoder_key_pack).unpack('C' + decoder_key_size.to_s)
	end

end

end

require 'msf/core/encoder/xor'
require 'msf/core/encoder/xor_additive_feedback'
