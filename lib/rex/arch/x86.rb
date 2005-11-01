#!/usr/bin/ruby

module Rex
module Arch

#
# everything here is mostly stole from vlad's perl x86 stuff
#

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

	REG_NAMES32 = [ 'eax', 'ecx', 'edx', 'ebx',
	                'esp', 'ebp', 'esi', 'edi' ]

	def self.jmp_short(addr)
		"\xeb" + pack_lsb(rel_number(addr, -2))
	end

	def self.call(addr)
		"\xe8" + pack_dword(rel_number(addr, -5))
	end

	def self.rel_number(num, delta = 0)
		s = num.to_s

		case s[0, 2]
			when '$+'
				num = s[2 .. -1].to_i
			when '$-'
				num = -1 * s[2 .. -1].to_i
			when '0x'
				num = s.hex
			else
				delta = 0
		end

		return num + delta
	end

	def self.reg_number(str)
		return self.const_get(str.upcase)
	end

	def self.reg_name32(num)
		_check_reg(num)
		return REG_NAMES32[num].dup
	end

	def self.encode_effective(shift, dst)
		return (0xc0 | (shift << 3) | dst)
	end

	def self.encode_modrm(dst, src)
		_check_reg(dst, src)
		return (0xc0 | src | dst << 3).chr
	end

	def self.push_byte(byte)
		# push byte will sign extend...
		if byte < 128 && byte >= -128
			return "\x6a" + (byte & 0xff).chr
		end
		raise ::ArgumentError, "Can only take signed byte values!", caller()
	end
	def self.pop_dword(dst)
		_check_reg(dst)
		return (0x58 | dst).chr
	end

	def self.clear(reg, badchars = '')
		_check_reg(reg)
		opcodes = Rex::StringUtils.remove_badchars("\x29\x2b\x31\x33", badchars)
		if opcodes.empty?
			raise RuntimeError, "Could not find a usable opcode", caller()
		end

		return opcodes[rand(opcodes.length)].chr + encode_modrm(reg, reg)
	end

	# B004 mov al,0x4
	def self.mov_byte(reg, val)
		_check_reg(reg)
		# chr will raise RangeError if val not between 0 .. 255
		return (0xb0 | reg).chr + val.chr
	end

	# 66B80400 mov ax,0x4
	def self.mov_word(reg, val)
		_check_reg(reg)
		if val < 0 || val > 0xffff
			raise RangeError, "Can only take unsigned word values!", caller()
		end
		return "\x66" + (0xb8 | reg).chr + [ val ].pack('v')
	end

	def self.set(dst, val, badchars = '')
		_check_reg(dst)

		# try push BYTE val; pop dst
		begin
			return _check_badchars(push_byte(val) + pop_dword(dst), badchars)
		rescue ::ArgumentError, RuntimeError, RangeError
		end

		# try clear dst, mov BYTE dst
		begin
			return _check_badchars(clear(dst, badchars) + mov_byte(dst, val), badchars)
		rescue ::ArgumentError, RuntimeError, RangeError
		end

		# try clear dst, mov WORD dst
		begin
			return _check_badchars(clear(dst, badchars) + mov_word(dst, val), badchars)
		rescue ::ArgumentError, RuntimeError, RangeError
		end

		raise RuntimeError, "No valid set instruction could be created!", caller()
	end

	#
	# Builds a subtraction instruction using the supplied operand
	# and register.
	#
	def self.sub(val, reg, badchars = '', add = false, adjust = false)
		opcodes = []
		shift   = (add == true) ? 0 : 5

		if (val >= -0x7f and val <= 0x7f)
			opcodes << 
				((adjust) ? '' : clear(reg, badchars)) + 
				"\x83" + 
				[ encode_effective(shift, reg) ].pack('C') +
				[ val.to_i ].pack('C')
		end

		if (val >= -0xffff and val <= 0)
			opcodes << 
				((adjust) ? '' : clear(reg, badchars)) + 
				"\x66\x81" + 
				[ encode_effective(shift, reg) ].pack('C') +
				[ val.to_i ].pack('v')
		end
			
		opcodes << 
			((adjust) ? '' : clear(reg, badchars)) + 
			"\x81" + 
			[ encode_effective(shift, reg) ].pack('C') +
			[ val.to_i ].pack('V')

		# Search for a compatible opcode
		opcodes.each { |op|
			begin 
				_check_badchars(op, badchars)
			rescue
				next
			end

			return op
		}

		if opcodes.empty?
			raise RuntimeError, "Could not find a usable opcode", caller()
		end
	end

	def self.add(val, reg, badchars = '', adjust = false)
		sub(val, reg, badchars, true, adjust)
	end

	def self.pack_dword(num)
		[num].pack('V')
	end

	def self.pack_lsb(num)
		pack_dword(num)[0,1]
	end

	def self.adjust_reg(adjustment)
		if (adjustment > 0)
			sub(adjustment, ESP, '', false, false)
		else
			add(adjustment, ESP, '', true, false)
		end
	end

	def self._check_reg(*regs)
		regs.each { |reg|
			if reg > 7 || reg < 0
				raise ArgumentError, "Invalid register #{reg}", caller()
			end
		}
		return nil
	end

	def self._check_badchars(data, badchars)
		idx = Rex::StringUtils.badchar_index(data, badchars)
		if idx
			raise RuntimeError, "Bad character at #{idx}", caller()
		end
		return data
	end

end

end end
