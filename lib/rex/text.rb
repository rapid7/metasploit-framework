module Rex

###
#
# Text
# ----
#
# This class formats text in various fashions and also provides
# a mechanism for wrapping text at a given column.
#
###
module Text

	DefaultWrap = 60

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

end
end
