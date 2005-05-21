require 'Core'

module Msf

###
#
# Nop
# ---
#
# This class acts as the base class for all nop generators.
#
###
class Nop < Msf::Module

	#
	# Stub method for generating a sled with the provided arguments.  Derived
	# Nop implementations must supply a length and can supply one or more of
	# the following options:
	#
	#   - Random (true/false)
	#     Indicates that the caller desires random NOPs (if supported).
	#   - SaveRegisters (array)
	#     The list of registers that should not be clobbered by the NOP
	#     generator.
	#   - Badchars (string)
	#     The list of characters that should be avoided by the NOP 
	#     generator.
	#
	def generate_sled(length, opts)
		return nil
	end

	# Default repetition threshold when find nop characters
	def nop_repeat_threshold
		return 10000
	end

end

end
