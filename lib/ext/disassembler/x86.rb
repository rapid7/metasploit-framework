module Ext
module Disassembler
module X86

require 'ext/disassembler/x86/dasm/dasm'

module Register
	#
	# Register number constants
	#
	EAX = AL = AX = ES = 0
	ECX = CL = CX = CS = 1
	EDX = DL = DX = SS = 2
	EBX = BL = BX = DS = 3
	ESP = AH = SP = FS = 4
	EBP = CH = BP = GS = 5
	ESI = DH = SI =      6
	EDI = BH = DI =      7

	module Type
		General = 1
		Segment = 2
		Debug   = 3
		Control = 4
		Test    = 5
		XMM     = 6
		MMX     = 7
		FPU     = 8
	end
end

module Operand
	
	module Type
		Memory    = 1
		Register  = 2
		Immediate = 3
	end

end

end
end
end
