require 'msf/core'

module Msf
module Encoders
module Cmd

class GenericSh < Msf::Encoder

	def initialize
		super(
			'Name'             => 'Generic Shell Variable Substitution Command Encoder',
			'Version'          => '$Revision$',
			'Description'      => %q{
				This encoder uses standard Bourne shell variable substitution
			tricks to avoid commonly restricted characters.
			},
			'Author'           => 'hdm',
			'Arch'             => ARCH_CMD)
	end

	
	#
	# Encodes the payload
	#
	def encode_block(state, buf)
		
		# Remove spaces from the command string
		if (state.badchars.include?(" "))
			buf.gsub!(/\s/, '${IFS}')
		end
		
		return buf
	end

end

end end end
