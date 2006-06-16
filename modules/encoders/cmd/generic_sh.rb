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

	#
	# Uses the perl command to hex encode the command string
	#
	def encode_block_perl(state, buf)

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
	
	#
	# Uses bash's echo -ne command to hex encode the command string
	#
	def encode_block_bash_echo(state, buf)
	
		hex = ''
		
		# Can we use single quotes to enclose the echo arguments?
		if (state.badchars.include?("'"))
			hex = buf.unpack('C*').collect { |c| "\\\\\\x%.2x" % c }.join
		else
			hex = "'" + buf.unpack('C*').collect { |c| "\\x%.2x" % c }.join + "'"
		end
		
		# Are pipe characters restricted?
		if (state.badchars.include?("|"))
			
			# How about backticks?
			if (state.badchars.include?("`"))
				raise RuntimeError
			else
				buf = "`echo -ne #{hex}`"
			end
		else
			buf = "echo -ne #{hex}|sh"
		end
		
		# Remove spaces from the command string
		if (state.badchars.include?(" "))
			buf.gsub!(/\s/, '${IFS}')
		end
		
		return buf
	end	

	
end

end end end
