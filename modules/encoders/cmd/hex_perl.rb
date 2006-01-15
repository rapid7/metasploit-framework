require 'msf/core'

module Msf
module Encoders
module Cmd

class HexPerl < Msf::Encoder

	def initialize
		super(
			'Name'             => 'PERL Hex Encoding',
			'Version'          => '$Revision$',
			'Description'      => %q{
				This encoder uses the PERL interpreter to decode
			and execute a command supplied in hex format. This encoder
			should work on most Unix systems that have PERL version
			5.0 or above.
			
			},
			'Author'           => 'hdm',
			'Arch'             => ARCH_CMD)
	end

	
	#
	# Encodes the payload
	#
	def encode_block(state, buf)

		hex = buf.unpack("H*")	
		cmd = 'perl -e '
		qot = ',-:.=+!@#$%^&'
		
		# Find a quoting character to use
		state.badchars.unpack('C*') { |c| quot.delete(c.chr) }
		
		# Throw an error if we ran out of quotes
		raise RuntimeError if qot.length == 0
		
		sep = qot[0].chr
		
		# Convert spaces to IFS...
		if (state.badchars.include?(" "))
			cmd.gsub!(/\s/, '${IFS}')
		end
		
		# Can we use single quotes to enclose the command string?
		if (state.badchars.include?("'"))
		
			if (state.badchars.match(/\(|\)/))

				# No paranthesis...
				raise RuntimeError
			end

			cmd << "system\\(pack\\(qq#{sep}H\\*#{sep},#{hex}\\)\\)"
				
		else
			if (state.badchars.match(/\(|\)/))
				if (state.badchars.include?(" "))
					# No spaces allowed, no paranthesis, give up...
					raise RuntimeError
				end
				
				cmd << "'system pack qq#{sep}H*#{sep},#{hex}'"
			else
				cmd << "'system(pack(qq#{sep}H*#{sep},#{hex}))'"
			end
		end
		
		return cmd
	end

end

end end end
