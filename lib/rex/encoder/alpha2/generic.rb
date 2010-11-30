#!/usr/bin/env ruby

require 'rex/text'

module Rex
module Encoder
module Alpha2

class Generic

	def Generic.default_accepted_chars ; ('a' .. 'z').to_a + ('B' .. 'Z').to_a + ('0' .. '9').to_a ; end

	def Generic.gen_decoder_prefix(reg, offset)
		# Should never happen - have to pick a specifc
		# encoding:
		# alphamixed, alphaupper, unicodemixed, unicodeupper
		''
	end

	def Generic.gen_decoder(reg, offset)
		# same as above
		return ''
	end

	def Generic.gen_base_set(ignored_max=0x0f)
		# 0xf is max for XOR encodings - non-unicode
		max = 0x0f
		Rex::Text.shuffle_a(
			[* ( (0..(max)).map { |i| i *= 0x10 } ) ]
		)
	end

	def Generic.gen_second(block, base)
		# XOR encoder for ascii - unicode uses additive
		(block^base)
	end

	def Generic.encode_byte(block, badchars)
		accepted_chars = default_accepted_chars.dup


		# Remove bad chars from the accepted_chars list.  Sadly 'A' must be
		# an accepted char or we'll certainly fail at this point.  This could
		# be fixed later maybe with some recalculation of the encoder stubs...
		# - Puss
		(badchars || '').unpack('C*').map { |c| accepted_chars.delete([c].pack('C')) }

		first    = 0
		second   = 1
		randbase = 0
		found    = nil


		gen_base_set(block).each do |randbase_|
			second   = gen_second(block, randbase_)
			next if second < 0
			if accepted_chars.include?([second].pack('C'))
				found    = second
				randbase = randbase_
				break
			end
		end

		if not found
			msg = "No valid base found for #{"0x%.2x" % block}"
			if not accepted_chars.include?([second].pack('C'))
				msg << ": BadChar to #{second}"
			elsif second < 1
				msg << ": Negative"
			end
			raise RuntimeError, msg
		end

		if (randbase > 0xa0)
			# first num must be 4
			first = (randbase/0x10) + 0x40
		elsif (randbase == 0x00) || (randbase == 0x10)
			# first num must be 5
			first = (randbase/0x10) + 0x50
		else
			# pick one at "random"
			first = (randbase/0x10)
			if (first % 2) > 0
				first += 0x40
			else
				first += 0x50
			end
		end

		# now add our new bytes :)
		[first.to_i, second].pack('CC')
	end

	def Generic.encode(buf, reg, offset, badchars = '')
		encoded = gen_decoder(reg, offset)

		buf.each_byte {
			|block|

			encoded += encode_byte(block, badchars)
		}

		encoded += add_terminator()

		return encoded
	end

	# 'A' signifies the end of the encoded shellcode
	def Generic.add_terminator()
		'AA'
	end

end end end end

