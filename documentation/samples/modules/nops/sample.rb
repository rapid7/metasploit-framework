require 'msf/core'

module Msf
module Nops

###
#
# This class implements a very basic NOP sled generator that just returns a
# string of 0x90's.
#
###
class Sample < Msf::Nop

	def initialize
		super(
			'Name'        => 'Sample NOP generator',
			'Version'     => '$Revision$',
			'Description' => 'Sample single-byte NOP generator',
			'Author'      => 'skape',
			'Arch'        => ARCH_X86)
	end

	#
	# Returns a string of 0x90's for the supplied length.
	#
	def generate_sled(length, opts)
		"\x90" * length
	end

end

end 
end
