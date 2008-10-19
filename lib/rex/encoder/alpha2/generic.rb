#!/usr/bin/env ruby

require 'rex/text'

module Rex
module Encoder
module Alpha2

class Generic
		
	@@default_accepted_chars = ('a' .. 'z').to_a + ('B' .. 'Z').to_a + ('0' .. '9').to_a
	
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
			[* ( (0..(max-1)).map { |i| i *= 0x10 } ) ]
		)
	end

	def Generic.gen_second(block, base)
		# XOR encoder for ascii - unicode uses additive
		(block^base)
	end

	def Generic.encode_byte(block, badchars)
		accepted_chars = @@default_accepted_chars.dup
		
		# Remove bad chars from the accepted_chars list.  Sadly 'A' must be 
		# an accepted char or we'll certainly fail at this point.  This could
		# be fixed later maybe with some recalculation of the encoder stubs...
		# - Puss
		(badchars || '').split('').each { |c| accepted_chars.delete(c) }

		first    = 0
		second   = 1
		randbase = 0
		
		gen_base_set(block).each do |randbase|
			second   = gen_second(block, randbase)
			next  if second < 0
			break if accepted_chars.include?(second.chr)
		end
		
		raise RuntimeError, "Negative" if second < 0
		raise RuntimeError, "BadChar; #{block} to #{second}"  if not accepted_chars.include?(second.chr)

		if (randbase > 0xa0)
			# first num must be 4
			first = (randbase/0x10) + 0x40
		elsif (randbase == 0x00) || (randbase == 0x10)
			# first num must be 5
			first = (randbase/0x10) + 0x50
		else
			# pick one at "random"
			first = (randbase/0x10)
			if (first % 2)
				first += 0x40
			else
				randbase += 0x50
			end
		end

		# now add our new bytes :)
		first.to_i.chr + second.chr
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