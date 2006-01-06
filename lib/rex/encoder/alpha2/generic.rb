#!/usr/bin/env ruby

require 'rex/text'

module Rex
module Encoder
module Alpha2

class Generic
	@@accepted_chars = ('a' .. 'z').to_a + ('B' .. 'Z').to_a + ('0' .. '9').to_a
    
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

	def Generic.gen_base(max)
		# 0xf is max for XOR encodings - non-unicode
		max = 0xf

		(rand(max) * 0x10)
	end

	def Generic.gen_second(block, base)
		# XOR encoder for ascii - unicode uses additive
		(block^base)
	end

	def Generic.encode_byte(block)
		first   = 0
		second  = 1

		while ( !(@@accepted_chars.include?(second.chr)) )
			randbase = gen_base(block)
			second = gen_second(block, randbase)
		end

		if (randbase > 0xa0)
			# first num must be 4
			first = (randbase/0x10) + 0x40
		elsif (randbase == 0x00)
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

	def Generic.encode(buf, reg, offset)
		encoded = gen_decoder(reg, offset)

		buf.each_byte {
			|block|

			encoded += encode_byte(block)
		}

		encoded += add_terminator()

		return encoded        
	end

	# 'A' signifies the end of the encoded shellcode
	def Generic.add_terminator()
		'AA'
	end

end end end end
