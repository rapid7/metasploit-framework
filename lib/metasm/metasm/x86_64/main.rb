#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/ia32'

module Metasm

# The x86_64, 64-bit extension of the x86 CPU (x64, em64t, amd64...)
class X86_64 < Ia32
	# SegReg, Farptr unchanged

	# no more floating point registers (use sse*)
	FpReg = nil

	# Simd extended to 16 regs, xmm only (mmx gone with 80387)
	class SimdReg < Ia32::SimdReg
		double_map 128 => (0..15).map { |n| "xmm#{n}" }
	end

	# general purpose registers, all sizes
	# 8 new gprs (r8..r15), set bit R in the REX prefix to reference them (or X/B if in ModRM)
	# aonethusaontehsanothe with 8bit subreg: with no rex prefix, refers to ah ch dh bh (as usual)
	#  but whenever the prefix is present, those become unavailable and encodie spl..dil (low byte of rsp/rdi)
	class Reg < Ia32::Reg
		double_map  8 => %w{ al  cl  dl  bl spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b ah ch dh bh},
			   16 => %w{ ax  cx  dx  bx  sp  bp  si  di r8w r9w r10w r11w r12w r13w r14w r15w},
			   32 => %w{eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d eip},
			   64 => %w{rax rcx rdx rbx rsp rbp rsi rdi r8  r9  r10  r11  r12  r13  r14  r15  rip}

		Sym = @i_to_s[64].map { |s| s.to_sym }

		# returns a symbolic representation of the register:
		# cx => :rcx & 0xffff
		# ah => (:rax >> 8) & 0xff
		# XXX in x64, 32bits operations are zero-extended to 64bits (eg mov rax, 0x1234_ffff_ffff ; add eax, 1 => rax == 0
		def symbolic(di=nil)
			s = Sym[@val]
			s = di.next_addr if s == :rip and di
			if @sz == 8 and to_s[-1] == ?h
				Expression[[Sym[@val-16], :>>, 8], :&, 0xff]
			elsif @sz == 8
				Expression[s, :&, 0xff]
			elsif @sz == 16
				Expression[s, :&, 0xffff]
			elsif @sz == 32
				Expression[s, :&, 0xffffffff]
			else
				s
			end
		end

		# checks if two registers have bits in common
		def share?(other)
			raise 'TODO'
			# XXX TODO wtf does formula this do ?
			other.val % (other.sz >> 1) == @val % (@sz >> 1) and (other.sz != @sz or @sz != 8 or other.val == @val)
		end

		# returns the part of @val to encode in an instruction field
		def val_enc
			if @sz == 8 and @val >= 16; @val-12	# ah, bh, ch, dh
			elsif @val >= 16			# rip
			else @val & 7				# others
			end
		end

		# returns the part of @val to encode in an instruction's rex prefix
		def val_rex
			if @sz == 8 and @val >= 16		# ah, bh, ch, dh: rex forbidden
			elsif @val >= 16			# rip
			else @val >> 3				# others
			end
		end
	end

	# ModRM represents indirections (eg dword ptr [eax+4*ebx+12h])
	# 16bit mode unavailable in x64
	# opcodes use 64bit addressing by default, use adsz override (67h) prefix to switch to 32
	# immediate values are encoded as :i32 sign-extended to 64bits
	class ModRM < Ia32::ModRM
		# mod 0/1/2 m 4 => sib
		# mod 0 m 5 => rip+imm
		# sib: i 4 => no index, b 5 => no base
	end

	class DbgReg < Ia32::DbgReg
		simple_map((0..15).map { |i| [i, "dr#{i}"] })
	end

	class CtrlReg < Ia32::CtrlReg
		simple_map((0..15).map { |i| [i, "cr#{i}"] })
	end

	# Create a new instance of an X86 cpu
	# arguments (any order)
	# - instruction set (386, 486, sse2...) [latest]
	# - endianness [:little]
	def initialize(*a)
		super(:latest)
		@size = 64
		a.delete @size
		@endianness = (a & [:big, :little]).first || :little
		a.delete @endianness
		@family = a.pop || :latest
		raise "Invalid arguments #{a.inspect}" if not a.empty?
		raise "Invalid X86_64 family #{@family.inspect}" if not respond_to?("init_#@family")
	end

	# defines some preprocessor macros to say who we are:
	# TODO
	def tune_prepro(pp)
		super(pp, :itsmeX64)	# ask Ia32's to just call super()
		pp.define_weak('_M_AMD64')
		pp.define_weak('_M_X64')
		pp.define_weak('__amd64__')
		pp.define_weak('__x86_64__')
	end

	def str_to_reg(str)
		# X86_64::Reg != Ia32::Reg
		Reg.from_str(str) if Reg.s_to_i.has_key? str
	end

	def shortname
		"x64#{'_be' if @endianness == :big}"
	end
end

X64 = X86_64
AMD64 = X86_64

end
