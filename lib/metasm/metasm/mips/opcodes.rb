#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/mips/main'

# TODO coprocessors, floating point, 64bits, thumb mode

module Metasm

class MIPS
	def addop(name, bin, *args)
		o = Opcode.new name, bin
		o.args.concat(args & @fields_mask.keys)
		(args & @valid_props).each { |p| o.props[p] = true }
		@opcode_list << o
	end

	def init_mips32_obsolete
		addop 'beql', 0b010100 << 26, :rt,   :rs, :i16, :setip	# == , exec delay slot only if jump taken
		addop 'bnel', 0b010101 << 26, :rt,   :rs, :i16, :setip	# !=
		addop 'blezl',0b010110 << 26, :rt_z, :rs, :i16, :setip	# <= 0
		addop 'bgtzl',0b010111 << 26, :rt_z, :rs, :i16, :setip	# > 0
		addop 'bltzl',1 << 26 | 0b00010 << 16, :rs, :i16, :setip
		addop 'bgezl',1 << 26 | 0b00011 << 16, :rs, :i16, :setip
		addop 'bltzall', 1 << 26 | 0b10010 << 16, :rs, :i16, :setip
		addop 'bgezall', 1 << 26 | 0b10011 << 16, :rs, :i16, :setip
	end

	def init_mips32_reserved
		addop 'future111011', 0b111011 << 26, :i26

		%w[011000 011001 011010 011011  100111 101100 101101 110100 110111 111100 111111].each { |b|
			addop "reserved#{b}", b.to_i(2) << 26, :i26
		}

		addop 'ase_jalx', 0b011101 << 26, :i26
		addop 'ase011110', 0b011110 << 26, :i26
		# TODO add all special/regimm/...
	end

	def init_mips32
		@opcode_list = []
		@fields_mask.update :rs => 0x1f, :rt => 0x1f, :rd => 0x1f, :sa => 0x1f,
			:i16 => 0xffff, :i26 => 0x3ffffff, :rs_i16 => 0x3e0ffff, :it => 0x1f,
			:ft => 0x1f, :idm1 => 0x1f, :idb => 0x1f, :sel => 7, :i20 => 0xfffff #, :i32 => 0
		@fields_shift.update :rs => 21, :rt => 16, :rd => 11, :sa => 6,
			:i16 => 0, :i26 => 0, :rs_i16 => 0, :it => 16,
			:ft => 16, :idm1 => 11, :idb => 11, :sel => 0, :i20 => 6 #, :i32 => 0

		init_mips32_obsolete
		init_mips32_reserved

		addop 'j',    0b000010 << 26, :i26, :setip, :stopexec	# sets the program counter to (i26 << 2) | ((pc+4) & 0xfc000000) ie i26*4 in the 256M-aligned section containing the instruction in the delay slot
		addop 'jal',  0b000011 << 26, :i26, :setip, :stopexec, :saveip	# same thing, saves return addr in r31

		addop 'mov',  0b001000 << 26, :rt, :rs			# rt <- rs+0
		addop 'addi', 0b001000 << 26, :rt, :rs, :i16		# add		rt <- rs+i
		addop 'li',   0b001001 << 26, :rt, :i16			# add $0	# XXX liu ?
		addop 'addiu',0b001001 << 26, :rt, :rs, :i16		# add unsigned
		addop 'slti', 0b001010 << 26, :rt, :rs, :i16		# set on less than
		addop 'sltiu',0b001011 << 26, :rt, :rs, :i16		# set on less than unsigned
		addop 'andi', 0b001100 << 26, :rt, :rs, :i16		# and
		addop 'li',   0b001101 << 26, :rt, :i16			# or $0
		addop 'ori',  0b001101 << 26, :rt, :rs, :i16		# or
		addop 'xori', 0b001110 << 26, :rt, :rs, :i16		# xor
		addop 'lui',  0b001111 << 26, :rt, :i16			# load upper
#		addop 'li',   (0b001111 << 26) << 32 | (0b001101 << 26), :rt_64, :i32			# lui + ori

		addop 'b',    0b000100 << 26, :i16, :setip, :stopexec	# bz $zero
		addop 'bz',   0b000100 << 26, :rs, :i16, :setip		# == 0	(beq $0)
		addop 'bz',   0b000100 << 26, :rt, :i16, :setip		# == 0
		addop 'bnz',  0b000101 << 26, :rs, :i16, :setip		# != 0
		addop 'bnz',  0b000101 << 26, :rt, :i16, :setip		# != 0

		addop 'beq',  0b000100 << 26, :rt, :rs, :i16, :setip	# ==
		addop 'bne',  0b000101 << 26, :rt, :rs, :i16, :setip	# !=
		addop 'blez', 0b000110 << 26, :rs, :i16, :setip		# <= 0
		addop 'bgtz', 0b000111 << 26, :rs, :i16, :setip		# > 0

		addop 'lb',   0b100000 << 26, :rt, :rs_i16		# load byte	rs <- [rt+i]
		addop 'lh',   0b100001 << 26, :rt, :rs_i16		# load halfword
		addop 'lwl',  0b100010 << 26, :rt, :rs_i16		# load word left
		addop 'lw',   0b100011 << 26, :rt, :rs_i16		# load word
		addop 'lbu',  0b100100 << 26, :rt, :rs_i16		# load byte unsigned
		addop 'lhu',  0b100101 << 26, :rt, :rs_i16		# load halfword unsigned
		addop 'lwr',  0b100110 << 26, :rt, :rs_i16		# load word right

		addop 'sb',   0b101000 << 26, :rt, :rs_i16		# store byte
		addop 'sh',   0b101001 << 26, :rt, :rs_i16		# store halfword
		addop 'swl',  0b101010 << 26, :rt, :rs_i16		# store word left
		addop 'sw',   0b101011 << 26, :rt, :rs_i16		# store word
		addop 'swr',  0b101110 << 26, :rt, :rs_i16		# store word right

		addop 'll',   0b110000 << 26, :rt, :rs_i16		# load linked word (read for atomic r/modify/w, sc does the w)
		addop 'sc',   0b111000 << 26, :rt, :rs_i16		# store conditional word

		addop 'lwc1', 0b110001 << 26, :ft, :rs_i16		# load word in fpreg low
		addop 'swc1', 0b111001 << 26, :ft, :rs_i16		# store low fpreg word
		addop 'lwc2', 0b110010 << 26, :rt, :rs_i16		# load word to copro2 register low
		addop 'swc2', 0b111010 << 26, :rt, :rs_i16		# store low coproc2 register

		addop 'ldc1', 0b110101 << 26, :ft, :rs_i16		# load dword in fpreg low
		addop 'sdc1', 0b111101 << 26, :ft, :rs_i16		# store fpreg
		addop 'ldc2', 0b110110 << 26, :rt, :rs_i16		# load dword to copro2 register
		addop 'sdc2', 0b111110 << 26, :rt, :rs_i16		# store coproc2 register

		addop 'pref', 0b110011 << 26, :it, :rs_i16		# prefetch (it = %w[load store r2 r3 load_streamed store_streamed load_retained store_retained
									# r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23 r24 writeback_invalidate
									# id26 id27 id28 id29 prepare_for_store id31]
		addop 'cache',0b101111 << 26, :it, :rs_i16		# do things with the proc cache

		# special
		addop 'nop',  0
		addop 'ssnop',1<<6
		addop 'ehb',  3<<6
		addop 'sll',  0b000000, :rd, :rt, :sa
		addop 'movf', 0b000001, :rd, :rs, :cc
		addop 'movt', 0b000001 | (1<<16), :rd, :rs, :cc
		addop 'srl',  0b000010, :rd, :rt, :sa
		addop 'sra',  0b000011, :rd, :rt, :sa
		addop 'sllv', 0b000100, :rd, :rt, :rs
		addop 'srlv', 0b000110, :rd, :rt, :rs
		addop 'srav', 0b000111, :rd, :rt, :rs

		addop 'jr',   0b001000, :rs, :setip, :stopexec			# hint field ?
		addop 'jr.hb',0b001000 | (1<<10), :rs, :setip, :stopexec
		addop 'jalr', 0b001001 | (31<<11), :rs, :setip, :stopexec, :saveip	# rd = r31 implicit
		addop 'jalr', 0b001001, :rd, :rs, :setip, :stopexec, :saveip
		addop 'jalr.hb', 0b001001 | (1<<10) | (31<<11), :rs, :setip, :stopexec, :saveip
		addop 'jalr.hb', 0b001001 | (1<<10), :rd, :rs, :setip, :stopexec, :saveip
		addop 'movz', 0b001010, :rd, :rs, :rt			# rt == 0 ? rd <- rs
		addop 'movn', 0b001011, :rd, :rs, :rt
		addop 'syscall', 0b001100, :i20
		addop 'break',0b001101, :i20, :stopexec
		addop 'sync', 0b001111					# type 0 implicit
		addop 'sync', 0b001111, :sa

		addop 'mfhi', 0b010000, :rd				# copies special reg HI to reg
		addop 'mthi', 0b010001, :rs				# copies reg to special reg HI
		addop 'mflo', 0b010010, :rd				# copies special reg LO to reg
		addop 'mtlo', 0b010011, :rs				# copies reg to special reg LO

		addop 'mult', 0b011000, :rs, :rt			# multiplies the registers and store the result in HI:LO
		addop 'multu',0b011001, :rs, :rt
		addop 'div',  0b011010, :rs, :rt
		addop 'divu', 0b011011, :rs, :rt
		addop 'add',  0b100000, :rd, :rs, :rt
		addop 'addu', 0b100001, :rd, :rs, :rt
		addop 'sub',  0b100010, :rd, :rs, :rt
		addop 'subu', 0b100011, :rd, :rs, :rt
		addop 'and',  0b100100, :rd, :rs, :rt
		addop 'or',   0b100101, :rd, :rs, :rt
		addop 'xor',  0b100110, :rd, :rs, :rt
		addop 'not',  0b100111, :rd, :rt			# nor $0
		addop 'not',  0b100111, :rd, :rs
		addop 'nor',  0b100111, :rd, :rs, :rt

		addop 'slt',  0b101010, :rd, :rs, :rt			# rs<rt ? rd<-1 : rd<-0
		addop 'sltu', 0b101011, :rd, :rs, :rt

		addop 'tge',  0b110000, :rs, :rt			# rs >= rt ? trap
		addop 'tgeu', 0b110001, :rs, :rt
		addop 'tlt',  0b110010, :rs, :rt
		addop 'tltu', 0b110011, :rs, :rt
		addop 'teq',  0b110100, :rs, :rt
		addop 'tne',  0b110110, :rs, :rt


		# regimm
		addop 'bltz', (1<<26) | (0b00000<<16), :rs, :i16, :setip
		addop 'bgez', (1<<26) | (0b00001<<16), :rs, :i16, :setip
		addop 'tgei', (1<<26) | (0b01000<<16), :rs, :i16, :setip
		addop 'tgfiu',(1<<26) | (0b01001<<16), :rs, :i16, :setip
		addop 'tlti', (1<<26) | (0b01010<<16), :rs, :i16, :setip
		addop 'tltiu',(1<<26) | (0b01011<<16), :rs, :i16, :setip
		addop 'teqi', (1<<26) | (0b01100<<16), :rs, :i16, :setip
		addop 'tnei', (1<<26) | (0b01110<<16), :rs, :i16, :setip
		addop 'bltzal', (1<<26) | (0b10000<<16), :rs, :i16, :setip, :saveip
		addop 'bgezal', (1<<26) | (0b10001<<16), :i16, :setip, :stopexec, :saveip	# bgezal $zero => unconditionnal
		addop 'bgezal', (1<<26) | (0b10001<<16), :rs, :i16, :setip, :saveip


		# special2
		addop 'madd', (0b011100<<26) | 0b000000, :rs, :rt
		addop 'maddu',(0b011100<<26) | 0b000001, :rs, :rt
		addop 'mul',  (0b011100<<26) | 0b000010, :rd, :rs, :rt
		addop 'msub', (0b011100<<26) | 0b000100, :rs, :rt
		addop 'msubu',(0b011100<<26) | 0b000101, :rs, :rt
		addop 'clz',  (0b011100<<26) | 0b100000, :rd, :rs, :rt	# must have rs == rt
		addop 'clo',  (0b011100<<26) | 0b100001, :rd, :rs, :rt	# must have rs == rt
		addop 'sdbbp',(0b011100<<26) | 0b111111, :i20


		# cp0
		addop 'mfc0', (0b010000<<26) | (0b00000<<21), :rt, :rd
		addop 'mfc0', (0b010000<<26) | (0b00000<<21), :rt, :rd, :sel
		addop 'mtc0', (0b010000<<26) | (0b00100<<21), :rt, :rd
		addop 'mtc0', (0b010000<<26) | (0b00100<<21), :rt, :rd, :sel

		addop 'tlbr', (0b010000<<26) | (1<<25) | 0b000001
		addop 'tlbwi',(0b010000<<26) | (1<<25) | 0b000010
		addop 'tlbwr',(0b010000<<26) | (1<<25) | 0b000110
		addop 'tlbp', (0b010000<<26) | (1<<25) | 0b001000
		addop 'eret', (0b010000<<26) | (1<<25) | 0b011000
		addop 'deret',(0b010000<<26) | (1<<25) | 0b011111
		addop 'wait', (0b010000<<26) | (1<<25) | 0b100000	# mode field ?
	end

	def init_mips32r2
		init_mips32

		addop 'rotr', 0b000010 | (1<<21), :rd, :rt, :sa
		addop 'rotrv',0b000110 | (1<<6), :rd, :rt, :rs

		addop 'synci',(1<<26) | (0b11111<<16), :rs_i16

		# special3
		addop 'ext', (0b011111<<26) | 0b000000, :rt, :rs, :sa, :idm1
		addop 'ins', (0b011111<<26) | 0b000100, :rt, :rs, :sa, :idb
		addop 'rdhwr',(0b011111<<26)| 0b111011, :rt, :rd
		addop 'wsbh',(0b011111<<26) | (0b00010<<6) | 0b100000, :rd, :rt
		addop 'seb', (0b011111<<26) | (0b10000<<6) | 0b100000, :rd, :rt
		addop 'seh', (0b011111<<26) | (0b11000<<6) | 0b100000, :rd, :rt

		# cp0
		addop 'rdpgpr', (0b010000<<26) | (0b01010<<21), :rd, :rt
		addop 'wrpgpr', (0b010000<<26) | (0b01110<<21), :rd, :rt
		addop 'di',     (0b010000<<26) | (0b01011<<21) | (0b01100<<11) | (0<<5)
		addop 'di',     (0b010000<<26) | (0b01011<<21) | (0b01100<<11) | (0<<5), :rt
		addop 'ei',     (0b010000<<26) | (0b01011<<21) | (0b01100<<11) | (1<<5)
		addop 'ei',     (0b010000<<26) | (0b01011<<21) | (0b01100<<11) | (1<<5), :rt
	end
	alias init_latest init_mips32r2
end
end
__END__
	def macro_addop_cop1(name, bin, *aprops)
		flds = [ :rt, :fs ]
		addop name, :cop1, bin, 'rt, fs', flds, *aprops
	end

	def macro_addop_cop1_precision(name, type, bin, fmt, *aprops)
		flds = [ :ft, :fs, :fd ]
		addop name+'.'+(type.to_s[5,7]), type, bin, fmt, flds, *aprops
	end


	public
	# Initialize the instruction set with the MIPS32 Instruction Set
	def init_mips32
					:cc => [7, 18, :fpcc],
					:op => [0x1F, 16, :op ], :cp2_rt => [0x1F, 16, :cp2_reg ],
					:stype => [0x1F, 6, :imm ],
					:code => [0xFFFFF, 6, :code ],
					:sel => [3, 0, :sel ]})

		# ---------------------------------------------------------------
		# COP0, field rs
		# ---------------------------------------------------------------

		addop 'mfc0', :cop0, 0b00000, 'rt, rd, sel', [ :rt, :rd, :sel ]
		addop 'mtc0', :cop0, 0b00100, 'rt, rd, sel', [ :rt, :rd, :sel ]

		# ---------------------------------------------------------------
		# COP0 when rs=C0
		# ---------------------------------------------------------------

		macro_addop_cop0_c0 'tlbr',  0b000001
		macro_addop_cop0_c0 'tlbwi', 0b000010
		macro_addop_cop0_c0 'tlwr',  0b000110
		macro_addop_cop0_c0 'tlbp',  0b001000
		macro_addop_cop0_c0 'eret',  0b011000
		macro_addop_cop0_c0 'deret', 0b011111
		macro_addop_cop0_c0 'wait',  0b100000

		# ---------------------------------------------------------------
		# COP1, field rs
		# ---------------------------------------------------------------

		macro_addop_cop1 'mfc1', 0b00000
		macro_addop_cop1 'cfc1', 0b00010
		macro_addop_cop1 'mtc1', 0b00100
		macro_addop_cop1 'ctc1', 0b00110

		addop "bc1f",  :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 0 ]
		addop "bc1fl", :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 2 ]
		addop "bc1t",  :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 1 ]
		addop "bc1tl", :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 3 ]

		# ---------------------------------------------------------------
		# COP1, field rs=S/D
		# ---------------------------------------------------------------

		[ :cop1_s, :cop1_d ].each do |type|
		type_str = type.to_s[5,7]

		macro_addop_cop1_precision 'add',  type, 0b000000, 'fd, fs, ft'
		macro_addop_cop1_precision 'sub',  type, 0b000001, 'fd, fs, ft'
		macro_addop_cop1_precision 'mul',  type, 0b000010, 'fd, fs, ft'
		macro_addop_cop1_precision 'abs',  type, 0b000101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'mov',  type, 0b000110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'neg',  type, 0b000111, 'fd, fs', :ft_zero

		macro_addop_cop1_precision 'movz', type, 0b010010, 'fd, fs, ft'
		macro_addop_cop1_precision 'movn', type, 0b010011, 'fd, fs, ft'

		addop "movf.#{type_str}", type, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ], :diff_bits, [ 16, 1, 0 ]
		addop "movt.#{type_str}", type, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ], :diff_bits, [ 16, 1, 1 ]

		%w(f un eq ueq olt ult ole ule sf ngle seq ngl lt nge le ngt).each_with_index do |cond, index|
			addop "c.#{cond}.#{type_str}", type, 0b110000+index, 'cc, fs, ft',
			[ :ft, :fs, :cc ]
		end
		end

		# S and D Without PS

		[:cop1_s, :cop1_d].each do |type|
		macro_addop_cop1_precision 'div',  type, 0b000011, 'fd, fs, ft'
		macro_addop_cop1_precision 'sqrt', type, 0b000100, 'fd, fs', :ft_zero

		macro_addop_cop1_precision 'round.w', type, 0b001100, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'trunc.w', type, 0b001101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'ceil.w',  type, 0b001110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'floor.w', type, 0b001111, 'fd, fs', :ft_zero

		end

		# COP2 is not decoded (pretty useless)

		[:cop1_d,:cop1_w].each { |type| macro_addop_cop1_precision 'cvt.s', type, 0b100000, 'fd, fs', :ft_zero }
		[:cop1_s,:cop1_w].each { |type| macro_addop_cop1_precision 'cvt.d', type, 0b100001, 'fd, fs', :ft_zero }
		[:cop1_s,:cop1_d].each { |type| macro_addop_cop1_precision 'cvt.w', type, 0b100100, 'fd, fs', :ft_zero }

		[ :normal, :special, :regimm, :special2, :cop0, :cop0_c0, :cop1, :cop1_s,
		  :cop1_d, :cop1_w ].each \
			{ |t| @@opcodes_by_class[t] = opcode_list.find_all { |o| o.type == t } }
	end

	# Initialize the instruction set with the MIPS32 Instruction Set Release 2
	def init_mips64
		init_mips32

		#SPECIAL
		macro_addop_special "rotr",  0b000010, 'rd, rt, sa', :diff_bits, [ 26, 1, 1 ]
		macro_addop_special "rotrv", 0b000110, 'rd, rt, rs', :diff_bits, [ 6, 1, 1 ]

		# REGIMM
		addop "synci", :regimm, 0b11111, '', {:base => [5,21], :off => [16, 0] }

		# ---------------------------------------------------------------
		# SPECIAL3 opcode encoding of function field
		# ---------------------------------------------------------------

		addop "ext", :special3, 0b00000, 'rt, rs, pos, size', { :rs => [5, 21], :rt => [5, 16],
									:msbd => [5, 11], :lsb => [5, 6] }
		addop "ins", :special3, 0b00100, 'rt, rs, pos, size', { :rs => [5, 21], :rt => [5, 16],
									:msb => [5, 11], :lsb => [5, 6] }

		addop "rdhwr", :special3, 0b111011, 'rt, rd', { :rt => [5, 16], :rd => [5, 11] }

		addop "wsbh", :bshfl, 0b00010, 'rd, rt', { :rt => [5, 16], :rd => [5, 11] }
		addop "seb",  :bshfl, 0b10000, 'rd, rt', { :rt => [5, 16], :rd => [5, 11] }
		addop "seh",  :bshfl, 0b11000, 'rd, rt', { :rt => [5, 16], :rd => [5, 11] }

		# ---------------------------------------------------------------
		# COP0
		# ---------------------------------------------------------------

		addop "rdpgpr", :cop0, 0b01010, 'rt, rd', {:rt => [5, 16], :rd => [5, 11] }
		addop "wdpgpr", :cop0, 0b01110, 'rt, rd', {:rt => [5, 16], :rd => [5, 11] }
		addop "di",     :cop0, 0b01011, '', {}, :diff_bits, [ 5, 1 , 0]
		addop "ei",     :cop0, 0b01011, '', {}, :diff_bits, [ 5, 1 , 1]

		# ---------------------------------------------------------------
		# COP1, field rs
		# ---------------------------------------------------------------

		macro_addop_cop1 "mfhc1", 0b00011
		macro_addop_cop1 "mthc1", 0b00111

		# Floating point

		[:cop1_s, :cop1_d].each do |type|
		macro_addop_cop1_precision 'round.l', type, 0b001000, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'trunc.l', type, 0b001001, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'ceil.l',  type, 0b001010, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'floor.l', type, 0b001011, 'fd, fs', :ft_zero

		macro_addop_cop1_precision 'recip', type, 0b010101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'rsqrt', type, 0b010110, 'fd, fs', :ft_zero

		macro_addop_cop1_precision 'cvt.l', type, 0b100101, 'fd, fs', :ft_zero
		end
		macro_addop_cop1_precision 'cvt.ps', :cop1_s, 0b100110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'cvt.s', :cop1_l, 0b100000, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'cvt.d', :cop1_l, 0b100000, 'fd, fs', :ft_zero

		macro_addop_cop1_precision 'add',  :cop1_ps, 0b000000, 'fd, fs, ft'
		macro_addop_cop1_precision 'sub',  :cop1_ps, 0b000001, 'fd, fs, ft'
		macro_addop_cop1_precision 'mul',  :cop1_ps, 0b000010, 'fd, fs, ft'
		macro_addop_cop1_precision 'abs',  :cop1_ps, 0b000101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'mov',  :cop1_ps, 0b000110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'neg',  :cop1_ps, 0b000111, 'fd, fs', :ft_zero

		macro_addop_cop1_precision 'movz', :cop1_ps, 0b010010, 'fd, fs, ft'
		macro_addop_cop1_precision 'movn', :cop1_ps, 0b010011, 'fd, fs, ft'

		addop "movf.#{:cop1_ps_str}", :cop1_ps, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ]
		addop "movt.#{:cop1_ps_str}", :cop1_ps, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ]

		%w(f un eq ueq olt ult ole ule sf ngle seq ngl lt nge le ngt).each_with_index do |cond, index|
			addop "c.#{cond}.ps", :cop1_cond, 0b110000+index, 'cc, fs, ft',
			[ :ft, :fs, :cc ]

		# TODO: COP1X

		[ :special3, :bshfl, :cop1_l, :cop1_ps ].each \
			{ |t| @@opcodes_by_class[t] = opcode_list.find_all { |o| o.type == t } }
	end

	end

	# Reset all instructions
	def reset
		metaprops_allowed.clear
		args_allowed.clear
		props_allowed.clear
		fields_spec.clear
		opcode_list.clear
	end

end
	# Array containing all the supported opcodes
	attr_accessor :opcode_list

	init_mips32
end

end
