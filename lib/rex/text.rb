require 'base64'
require 'digest/md5'
require 'stringio'

begin
	require 'zlib'
rescue LoadError
end

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

	States = ["AK", "AL", "AR", "AZ", "CA", "CO", "CT", "DE", "FL", "GA", "HI",
		"IA", "ID", "IL", "IN", "KS", "KY", "LA", "MA", "MD", "ME", "MI", "MN",
		"MO", "MS", "MT", "NC", "ND", "NE", "NH", "NJ", "NM", "NV", "NY", "OH",
		"OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VA", "VT", "WA",
		"WI", "WV", "WY"]
	UpperAlpha   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	LowerAlpha   = "abcdefghijklmnopqrstuvwxyz"
	Numerals     = "0123456789"
	Alpha        = UpperAlpha + LowerAlpha
	AlphaNumeric = Alpha + Numerals
	HighAscii    = (0x80 .. 0xff).map { |b| [b].pack('C') }.to_s
	DefaultWrap  = 60
	AllChars	 = 	
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

	DefaultPatternSets = [ Rex::Text::UpperAlpha, Rex::Text::LowerAlpha, Rex::Text::Numerals ]
	
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
	# Creates a javascript-style comment
	#
	def self.to_js_comment(str, wrap = DefaultWrap)
		return wordwrap(str, 0, wrap, '', '// ')
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
	# Returns a unicode escaped string for Javascript
	#
	def self.to_unescape(data, endian=ENDIAN_LITTLE)
		data << "\x41" if (data.length % 2 != 0)
		dptr = 0
		buff = ''
		while (dptr < data.length)
			c1 = data[dptr]
			dptr += 1
			c2 = data[dptr]
			dptr += 1
			
			if (endian == ENDIAN_LITTLE)
				buff << sprintf('%%u%.2x%.2x', c2, c1)
			else
				buff << sprintf('%%u%.2x%.2x', c1, c2)
			end
		end
		return buff	
	end

	#
	# Returns the hex version of the supplied string
	#
	def self.to_hex(str, prefix = "\\x", count = 1)
		raise ::RuntimeError, "unable to chunk into #{count} byte chunks" if ((str.length % count) > 0)

		# XXX: Regexp.new is used here since using /.{#{count}}/o would compile
		# the regex the first time it is used and never check again.  Since we
		# want to know how many to capture on every instance, we do it this
		# way.
		return str.unpack('H*')[0].gsub(Regexp.new(".{#{count * 2}}")) { |s| prefix + s }
	end

	#
	# Converts standard ASCII text to a unicode string.  
	#
	# Supported unicode types include: utf-16le, utf16-be, utf32-le, utf32-be, utf-7, and utf-8
	# 
	# Providing 'mode' provides hints to the actual encoder as to how it should encode the string.  Only UTF-7 and UTF-8 use "mode".
	# 
	# utf-7 by default does not encode alphanumeric and a few other characters.  By specifying the mode of "all", then all of the characters are encoded, not just the non-alphanumeric set.
	#	to_unicode(str, 'utf-7', 'all')
	# 
	# utf-8 specifies that alphanumeric characters are used directly, eg "a" is just "a".  However, there exist 6 different overlong encodings of "a" that are technically not valid, but parse just fine in most utf-8 parsers.  (0xC1A1, 0xE081A1, 0xF08081A1, 0xF8808081A1, 0xFC80808081A1, 0xFE8080808081A1).  How many bytes to use for the overlong enocding is specified providing 'size'.
	# 	to_unicode(str, 'utf-8', 'overlong', 2)
	#
	# Many utf-8 parsers also allow invalid overlong encodings, where bits that are unused when encoding a single byte are modified.  Many parsers will ignore these bits, rendering simple string matching to be ineffective for dealing with UTF-8 strings.  There are many more invalid overlong encodings possible for "a".  For example, three encodings are available for an invalid 2 byte encoding of "a". (0xC1E1 0xC161 0xC121).  By specifying "invalid", a random invalid encoding is chosen for the given byte size.
	# 	to_unicode(str, 'utf-8', 'invalid', 2)
	#
	# utf-7 defaults to 'normal' utf-7 encoding
	# utf-8 defaults to 2 byte 'normal' encoding
	# 
	def self.to_unicode(str='', type = 'utf-16le', mode = '', size = '')
		case type 
		when 'utf-16le'
			return str.unpack('C*').pack('v*')
		when 'utf-16be'
			return str.unpack('C*').pack('n*')
		when 'utf-32le'
			return str.unpack('C*').pack('V*')
		when 'utf-32be'
			return str.unpack('C*').pack('N*')
		when 'utf-7'
			case mode
			when 'all'
				return str.gsub(/./){ |a|
					out = ''
					if 'a' != '+'
						out = encode_base64(to_unicode(a, 'utf-16be')).gsub(/[=\r\n]/, '')
					end
					'+' + out + '-'
				}
			else
				return str.gsub(/[^\n\r\t\ A-Za-z0-9\'\(\),-.\/\:\?]/){ |a| 
					out = ''
					if a != '+'
						out = encode_base64(to_unicode(a, 'utf-16be')).gsub(/[=\r\n]/, '')
					end
					'+' + out + '-'
				}
			end
		when 'utf-8'
			if size == ''
				size = 2
			end

			if size >= 2 and size <= 7
				string = ''
				str.each_byte { |a|
					if (a < 21 || a > 0x7f) || mode != ''
						# ugh.  turn a single byte into the binary representation of it, in array form
						bin = [a].pack('C').unpack('B8')[0].split(//)

						# even more ugh.
						bin.collect!{|a| a = a.to_i}

						out = Array.new(8 * size, 0)

						0.upto(size - 1) { |i|
							out[i] = 1
							out[i * 8] = 1
						}

						i = 0
						byte = 0
						bin.reverse.each { |bit|
							if i < 6
								mod = (((size * 8) - 1) - byte * 8) - i
								out[mod] = bit
							else 
								byte = byte + 1
								i = 0
								redo
							end
							i = i + 1
						}

						if mode != ''
							case mode
							when 'overlong'
								# do nothing, since we already handle this as above...
							when 'invalid'
								done = 0
								while done == 0
									# the ghetto...
									bits = [7, 8, 15, 16, 23, 24, 31, 32, 41]
									bits.each { |bit|
										bit = (size * 8) - bit
										if bit > 1
											set = rand(2)
											if out[bit] != set
												out[bit] = set
												done = 1
											end
										end
									}
								end
							else
								raise TypeError, 'Invalid mode.  Only "overlong" and "invalid" are acceptable modes for utf-8'
							end
						end
						string += [out.join('')].pack('B*')
					else
						string += [a].pack('C')
					end
				}
				return string
			else 
				raise TypeError, 'invalid utf-8 size'
			end
		when 'uhwtfms' # suggested name from HD :P
			load_codepage()

			string = ''
			# overloading mode as codepage
			if mode == ''
				mode = 1252 # ANSI - Latan 1, default for US installs of MS products
			else
				mode = mode.to_i
			end
			if $codepage_map_cache[mode].nil?
				raise TypeError, "Invalid codepage #{mode}"
			end
			str.each_byte {|byte|
				char = [byte].pack('C*')
				possible = $codepage_map_cache[mode]['data'][char]
				if possible.nil?
					raise TypeError, "codepage #{mode} does not provide an encoding for 0x#{char.unpack('H*')[0]}"
				end
				string += possible[ rand(possible.length) ]
			}
			return string
		else 
			raise TypeError, 'invalid utf type'
		end
	end

	# 	
	# Encode a string in a manor useful for HTTP URIs and URI Parameters.  
	#
	def self.uri_encode(str, mode = 'hex-normal')
		return str if mode == 'none' # fast track no encoding

		all = /[^\/\\]+/
        normal = /[^a-zA-Z1-9\/\/\\]+/

        case mode
        when 'hex-normal'
            return str.gsub(normal) { |s| Rex::Text.to_hex(s, '%') }
        when 'hex-all'
            return str.gsub(all) { |s| Rex::Text.to_hex(s, '%') }
        when 'u-normal'
            return str.gsub(normal) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) }
        when 'u-all'
            return str.gsub(all) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) }
        else
            raise TypeError, 'invalid mode'
        end
	end

	# Encode a string in a manor useful for HTTP URIs and URI Parameters.  
	# 
	# a = "javascript".gsub(/./) {|i| "(" + [ Rex::Text.html_encode(i, 'hex'), Rex::Text.html_encode(i, 'int'), Rex::Text.html_encode(i, 'int-wide')].join('|') +')[\s\x00]*' }
	def self.html_encode(str, mode = 'hex')
		case mode
		when 'hex'
			return str.gsub(/./) { |s| Rex::Text.to_hex(s, '&#x') }
		when 'int'
			return str.unpack('C*').collect{ |i| "&#" + i.to_s }.join('')
		when 'int-wide'
			return str.unpack('C*').collect{ |i| "&#" + ("0" * (7 - i.to_s.length)) + i.to_s }.join('')
		else 
			raise TypeError, 'invalid mode'
		end
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
		Base64.encode64(str).gsub(/\s+/, '')
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
		Digest::MD5.digest(str)	
	end

	#
	# Hexidecimal MD5 digest of the supplied string
	#
	def self.md5(str)
		Digest::MD5.hexdigest(str)
	end

	##
	#
	# Executable generators
	#
	##
	
	def self.to_win32pe(code = "\xcc", note="")
		pe = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "data", "templates", "template.exe"), "rb")
		pe = fd.read(fd.stat.size)
		fd.close

		bo = pe.index('PAYLOAD:')
		co = pe.index('COMMENT:')

		pe[bo, 8192] = [code].pack('a8192') if bo
		pe[co, 512]  = [note].pack('a512') if co

		return pe
	end
	
	##
	#
	# Generators
	#
	##

	# Generates a random character.
	def self.rand_char(bad, chars = AllChars)
		rand_text(1, bad, chars)	
	end
	
	# Base text generator method
	def self.rand_base(len, bad, *foo)
		# Remove restricted characters
		(bad || '').split('').each { |c| foo.delete(c) }

		# Return nil if all bytes are restricted
		return nil if foo.length == 0
	
		buff = ""
	
		# Generate a buffer from the remaining bytes
		if foo.length >= 256
			len.times { buff << Kernel.rand(256) }
		else 
			len.times { buff += foo[ rand(foo.length) ] }
		end

		return buff
	end

	# Generate random bytes of data
	def self.rand_text(len, bad='', chars = AllChars)
		foo = chars.split('')
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

	# Generate random bytes of english-like data
	def self.rand_text_english(len, bad='')
		foo = []
		foo += (0x21 .. 0x7e).map{ |c| c.chr }
		rand_base(len, bad, *foo )
	end
	
	#
	# Creates a pattern that can be used for offset calculation purposes.  This
	# routine is capable of generating patterns using a supplied set and a
	# supplied number of identifiable characters (slots).  The supplied sets
	# should not contain any duplicate characters or the logic will fail.
	#
	def self.pattern_create(length, sets = [ UpperAlpha, LowerAlpha, Numerals ])
		buf = ''
		idx = 0
		offsets = []

		sets.length.times { offsets << 0 }

		until buf.length >= length
			begin
				buf += converge_sets(sets, 0, offsets, length)
			rescue RuntimeError
				break
			end
		end

		buf[0..length]
	end

	#
	# Calculate the offset to a pattern
	#
	def self.pattern_offset(pattern, value)
		if (value.kind_of?(String))
			pattern.index(value)
		elsif (value.kind_of?(Fixnum) or value.kind_of?(Bignum))
			pattern.index([ value ].pack('V'))
		else
			raise ::ArgumentError, "Invalid class for value: #{value.class}"
		end
	end

	#
	# Compresses a string, eliminating all superfluous whitespace before and
	# after lines and eliminating all lines.
	#
	def self.compress(str)
		str.gsub(/\n/m, ' ').gsub(/\s+/, ' ').gsub(/^\s+/, '').gsub(/\s+$/, '')
	end

	# Returns true if zlib can be used.
	def self.zlib_present?
		begin
			temp = Zlib
			return true
		rescue
			return false
		end
	end
	
	# backwards compat for just a bit...
	def self.gzip_present?
		self.zlib_present?
	end

	#
	# Compresses a string using zlib
	#
	def self.zlib_deflate(str)
		raise RuntimeError, "Gzip support is not present." if (!zlib_present?)
		return Zlib::Deflate.deflate(str)
	end

	#
	# Uncompresses a string using zlib
	#
	def self.zlib_inflate(str)
		raise RuntimeError, "Gzip support is not present." if (!zlib_present?)
		return Zlib::Inflate.inflate(str)
	end

	#
	# Compresses a string using gzip
	#
	def self.gzip(str, level = 9)
		raise RuntimeError, "Gzip support is not present." if (!zlib_present?)
		raise RuntimeError, "Invalid gzip compression level" if (level < 1 or level > 9)

		s = ""
		gz = Zlib::GzipWriter.new(StringIO.new(s), level)
		gz << str
		gz.close
		return s
	end
	
	#
	# Uncompresses a string using gzip
	#
	def self.ungzip(str)
		raise RuntimeError, "Gzip support is not present." if (!zlib_present?)

		s = ""
		gz = Zlib::GzipReader.new(StringIO.new(str))
		s << gz.read
		gz.close
		return s
	end
	
	#
	# Return the index of the first badchar in data, otherwise return
	# nil if there wasn't any badchar occurences.
	#
	def self.badchar_index(data, badchars = '')
		badchars.each_byte { |badchar|
			pos = data.index(badchar)
			return pos if pos
		}
		return nil
	end

	#
	# This method removes bad characters from a string.
	#
	def self.remove_badchars(data, badchars = '')
		data.delete(badchars)
	end

	#
	# This method returns all chars but the supplied set
	#
	def self.charset_exclude(keepers)
		[*(0..255)].pack('C*').delete(keepers)
	end

	#
	#  Shuffles a byte stream
	#
	def self.shuffle_s(str)
		shuffle_a(str.unpack("C*")).pack("C*")
	end

	#
	# Performs a Fisher-Yates shuffle on an array
	#
	def self.shuffle_a(arr)
		len = arr.length
		max = len - 1
		cyc = [* (0..max) ]
		for d in cyc
			e = rand(d+1)
			next if e == d
			f = arr[d];
			g = arr[e];
			arr[d] = g;
			arr[e] = f;
		end
		return arr
	end

	# Generate a random hostname
	def self.rand_hostname
		host = []
		(rand(5) + 1).times {
			host.push(Rex::Text.rand_text_alphanumeric(rand(10) + 1))
		}
		d = ['com', 'net', 'org', 'gov']
		host.push(d[rand(d.size)])
		host.join('.').downcase
	end

	# Generate a state
	def self.rand_state()
		States[rand(States.size)]
	end

protected

	def self.converge_sets(sets, idx, offsets, length) # :nodoc:
		buf = sets[idx][offsets[idx]].chr

		# If there are more sets after use, converage with them.
		if (sets[idx + 1])
			buf += converge_sets(sets, idx + 1, offsets, length)
		else
			# Increment the current set offset as well as previous ones if we
			# wrap back to zero.
			while (idx >= 0 and ((offsets[idx] = (offsets[idx] + 1) % sets[idx].length)) == 0)
				idx -= 1
			end

			# If we reached the point where the idx fell below zero, then that
			# means we've reached the maximum threshold for permutations.
			if (idx < 0)
				raise RuntimeError, "Maximum permutations reached"
			end
		end

		buf
	end
	
	def self.load_codepage()
		return if (!$codepage_map_cache.nil?)
		file = File.join(File.dirname(__FILE__),'codepage.map')
		page = ''
		name = ''
		map = {}
		File.open(file).each { |line|
			next if line =~ /^#/
			next if line =~ /^\s*$/
			data = line.split
			if data[1] =~ /^\(/
				page = data.shift.to_i
				name = data.join(' ').sub(/^\(/,'').sub(/\)$/,'')
				map[page] = {}
				map[page]['name'] = name
				map[page]['data'] = {}
			else
				data.each { |entry|
					wide, char = entry.split(':')
					char = [char].pack('H*')
					wide = [wide].pack('H*')
					if map[page]['data'][char].nil?
						map[page]['data'][char] = [wide]
					else
						map[page]['data'][char].push(wide)
					end
				}
			end
		}
		$codepage_map_cache = map
	end

end
end
