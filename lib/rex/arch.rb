module Rex


###
#
# This module provides generalized methods for performing operations that are
# architecture specific.  Furthermore, the modules contained within this
# module provide features that are specific to a given architecture.
#
###
module Arch

	require 'rex/arch/x86'
	require 'rex/arch/sparc'

	#
	# This routine adjusts the stack pointer for a given architecture
	#
	def self.adjust_stack_pointer(arch, adjustment)
		case arch
			when /x86/
				Rex::Arch::X86.adjust_reg(adjustment, Rex::Arch::X86::ESP)
			else
				nil
		end
	end

end
end
