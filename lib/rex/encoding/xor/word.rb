#!/usr/bin/ruby

#
# Routine for xor encoding a buffer by a 2-byte (intel word) key.  The perl
# version used to pad this buffer out to a 2-byte boundary, but I can't think
# of a good reason to do that anymore, so this doesn't.
#

module Rex
module Encoding
module Xor

class Word < Generic

	def Word.find_key(*crap)
		raise NotImplementedError, "We are lazy bums!", caller
	end

	def Word.keylength
		return 2
	end

	def Word.packspec
		return 'v'
	end
	
	def Word.pack(num)
		[ num ].pack(packspec)
	end

	def Word.unpack(data)
		data.unpack(packspec)[0]
	end

	def Word.encode(buf, key)
		encoded = ""
		pos     = 0
		len     = keylength()

		while pos < buf.length
			chunk = buf[pos, len]
			short = len - length(chunk)

			# temporarly pad out if we are short of a word
			chunk .= "\x00" * short

			# add to the result, removing any short padding
			encoded += (pack(unpack(chunk) ^ key))[0, len - short]

			pos += len
		end
	end

	# maybe a bit a smaller of method name?
	def Word.find_key_and_encode()
	end



end end end end # Word/Xor/Encoding/Rex
