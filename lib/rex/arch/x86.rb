#!/usr/bin/ruby

module Rex
module Arch

module X86

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

	def self.reg_number(str)
		return self.const_get(str.upcase)
	end

	def self.push_byte(byte)
		# push byte will sign extend...
		if byte < 128 && byte >= -128
			return "\x6a" + (byte & 0xff).chr
		end
		raise ::ArgumentError, "Can only take signed byte values!", caller()
	end

	def self.check_reg(reg)
		if reg > 7 || reg < 0
			raise ArgumentError, "Invalid register #{reg}", caller()
		end
	end

	def self.pop_dword(dst)
		check_reg(dst)
		return (0x58 | dst).chr
	end

	def self.set(dst, val, badchars)
		# I'm a lazy bum fix this!"
		data = push_byte(val) + pop_dword(dst)
		return data
		# !!! check bad chars!
	end

end

end end
