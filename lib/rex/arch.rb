module Rex
module Arch

	require 'rex/arch/x86'

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
