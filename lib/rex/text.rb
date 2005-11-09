require 'base64'
require 'md5'

module Rex

###
#
# This class formats text in various fashions and also provides
# a mechanism for wrapping text at a given column.
#
###
module Text
	
	##
	#
	# Constants
	#
	##
	
	UpperAlpha   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	LowerAlpha   = "abcdefghijklmnopqrstuvwxyz"
	Numerals     = "0123456789"
	Alpha        = UpperAlpha + LowerAlpha
	AlphaNumeric = Alpha + Numerals
	DefaultWrap  = 60

	##
	#
	# Serialization
	#
	##

	#
	# Converts a raw string into a ruby buffer
	#
	def self.to_ruby(str, wrap = DefaultWrap)
		return hexify(str, wrap, '"', '" +', '', '"')
	end

	#
	# Creates a ruby-style comment
	#
	def self.to_ruby_comment(str, wrap = DefaultWrap)
		return wordwrap(str, 0, wrap, '', '# ')
	end

	#
	# Converts a raw string into a C buffer
	#
	def self.to_c(str, wrap = DefaultWrap, name = "buf")
		return hexify(str, wrap, '"', '"', "unsigned char #{name}[] = \n", '";')
	end

	#
	# Creates a c-style comment
	#
	def self.to_c_comment(str, wrap = DefaultWrap)
		return "/*\n" + wordwrap(str, 0, wrap, '', ' * ') + " */\n"
	end

	#
	# Converts a raw string into a perl buffer
	#
	def self.to_perl(str, wrap = DefaultWrap)
		return hexify(str, wrap, '"', '" .', '', '";')
	end

	#
	# Creates a perl-style comment
	#
	def self.to_perl_comment(str, wrap = DefaultWrap)
		return wordwrap(str, 0, wrap, '', '# ')
	end

	#
	# Returns the raw string
	#
	def self.to_raw(str)
		return str
	end

	#
	# Returns the hex version of the supplied string
	#
	def self.to_hex(str)
		return str.gsub(/./) { |s| puts sprintf("\\x%.2x", s[0]) }
	end

	#
	# Converts a hex string to a raw string
	#
	def self.hex_to_raw(str)
		[ str.downcase.gsub(/'/,'').gsub(/\\?x([a-f0-9][a-f0-9])/, '\1') ].pack("H*")
	end

	#
	# Wraps text at a given column using a supplied indention
	#
	def self.wordwrap(str, indent = 0, col = DefaultWrap, append = '', prepend = '')
		return str.gsub(/.{1,#{col - indent}}(?:\s|\Z)/){
			( (" " * indent) + prepend + $& + append + 5.chr).gsub(/\n\005/,"\n").gsub(/\005/,"\n")}
	end

	#
	# Converts a string to a hex version with wrapping support
	#
	def self.hexify(str, col = DefaultWrap, line_start = '', line_end = '', buf_start = '', buf_end = '')
		output   = buf_start
		cur      = 0
		count    = 0
		new_line = true

		# Go through each byte in the string
		str.each_byte { |byte|
			count  += 1
			append  = ''

			# If this is a new line, prepend with the
			# line start text
			if (new_line == true)
				append   += line_start
				new_line  = false
			end

			# Append the hexified version of the byte
			append += sprintf("\\x%.2x", byte)
			cur    += append.length

			# If we're about to hit the column or have gone past it,
			# time to finish up this line
			if ((cur + line_end.length >= col) or
			    (cur + buf_end.length  >= col))
				new_line  = true
				cur       = 0

				# If this is the last byte, use the buf_end instead of
				# line_end
				if (count == str.length)
					append += buf_end + "\n"
				else
					append += line_end + "\n"
				end
			end

			output += append
		}

		# If we were in the middle of a line, finish the buffer at this point
		if (new_line == false)
			output += buf_end + "\n"
		end	

		return output
	end

	##
	#
	# Transforms
	#
	##

	#
	# Base64 encoder
	#
	def self.encode_base64(str)
		Base64.encode64(str)
	end

	#
	# Base64 decoder
	#
	def self.decode_base64(str)
		Base64.decode64(str)
	end

	#
	# Raw MD5 digest of the supplied string
	#
	def self.md5_raw(str)
		MD5.digest(str)	
	end

	#
	# Hexidecimal MD5 digest of the supplied string
	#
	def self.md5(str)
		MD5.hexdigest(str)
	end

	##
	#
	# Generators
	#
	##
	
	# Base text generator method
	def self.rand_base(len, bad, *foo)
		# Remove restricted characters
		bad.split('').each { |c| foo.delete(c) }

		# Return nil if all bytes are restricted
		return nil if foo.length == 0

		# Generate a buffer from the remaining bytes
		buff = ""
		len.times { buff += foo[ rand(foo.length) ] }
		return buff
	end

	# Generate random bytes of data
	def self.rand_text(len, bad='')
		chr = 
		"\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c" +
		"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a" +
		"\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28" +
		"\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36" +
		"\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44" +
		"\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52" +
		"\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60" +
		"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e" +
		"\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c" +
		"\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a" +
		"\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98" +
		"\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6" +
		"\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4" +
		"\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2" +
		"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0" +
		"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde" +
		"\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec" +
		"\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa" +
		"\xfb\xfc\xfd\xfe"		
		foo = chr.split('')
		rand_base(len, bad, *foo)
	end

	# Generate random bytes of alpha data
	def self.rand_text_alpha(len, bad='')
		foo = []
		foo += ('A' .. 'Z').to_a
		foo += ('a' .. 'z').to_a
		rand_base(len, bad, *foo )
	end

	# Generate random bytes of lowercase alpha data
	def self.rand_text_alpha_lower(len, bad='')
		rand_base(len, bad, *('a' .. 'z').to_a)
	end

	# Generate random bytes of uppercase alpha data
	def self.rand_text_alpha_upper(len, bad='')
		rand_base(len, bad, *('A' .. 'Z').to_a)
	end

	# Generate random bytes of alphanumeric data
	def self.rand_text_alphanumeric(len, bad='')
		foo = []
		foo += ('A' .. 'Z').to_a
		foo += ('a' .. 'z').to_a
		foo += ('0' .. '9').to_a
		rand_base(len, bad, *foo )
	end

	#
	# Creates a pattern that can be used for offset calculation purposes.  This
	# routine is capable of generating patterns using a supplied set and a
	# supplied number of identifiable characters (slots).
	#
	def self.pattern_create(length, set = AlphaNumeric, num_slots = 4)
		positions = Array.new
		curr_pos  = 0
		buf       = ''

		num_slots.times { positions << 0 }

		while (buf.length < length)
			buf += (positions.collect { |pos| set[pos].chr }).join('')

			while ((positions[curr_pos] = (positions[curr_pos] + 1) % set.length) == 0)
				curr_pos = (curr_pos + 1) % positions.length
			end
		end

		(buf.length > length) ? buf.slice(0 .. length) : buf
	end

	#
	# Calculate the offset to a pattern
	#
	def self.pattern_offset(pattern, value)
		if (value.kind_of?(String))
			pattern.index(value)
		elsif (value.kind_of?(Fixnum))
			pattern.index([ value ].unpack('V')[0])
		else
			raise ArgumentError, "Invalid class for value: #{value.class}"
		end
	end

	#
	# Compresses a string, eliminating all superfluous whitespace before and
	# after lines and eliminating all lines.
	#
	def self.compress(str)
		str.gsub(/\n/m, ' ').gsub(/\s+/, ' ').gsub(/^\s+/, '').gsub(/\s+$/, '')
	end
	
	#
	# Return the index of the first badchar in data, otherwise return
	# nil if there wasn't any badchar occurences.
	#
	def self.badchar_index(data, badchars)
		badchars.each_byte { |badchar|
			pos = data.index(badchar)
			return pos if pos
		}
		return nil
	end

	#
	# This method removes bad characters from a string.
	#
	def self.remove_badchars(data, badchars)
		data.delete(badchars)
	end


end
end
