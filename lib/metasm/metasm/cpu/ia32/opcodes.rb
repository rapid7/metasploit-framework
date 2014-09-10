#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/ia32/main'

module Metasm
class Ia32
  def init_cpu_constants
    @opcode_list ||= []
    @fields_mask.update :w => 1, :s => 1, :d => 1, :modrm => 0xC7,
      :reg => 7, :eeec => 7, :eeed => 7, :eeet => 7, :seg2 => 3, :seg3 => 7,
      :regfp => 7, :regmmx => 7, :regxmm => 7, :regymm => 7,
      :vex_r => 1, :vex_b => 1, :vex_x => 1, :vex_w => 1,
      :vex_vvvv => 0xF
    @fields_mask[:seg2A]    = @fields_mask[:seg2]
    @fields_mask[:seg3A]    = @fields_mask[:seg3]

    [:i, :i8, :u8, :u16, :reg, :seg2, :seg2A,
     :seg3, :seg3A, :eeec, :eeed, :eeet, :modrm, :mrm_imm,
     :farptr, :imm_val1, :imm_val3, :reg_cl, :reg_eax,
     :reg_dx, :regfp, :regfp0, :modrmmmx, :regmmx,
     :modrmxmm, :regxmm, :modrmymm, :regymm,
     :vexvxmm, :vexvymm, :vexvreg, :i4xmm, :i4ymm
    ].each { |a| @valid_args[a] = true }

    [:strop, :stropz, :opsz, :adsz, :argsz, :setip,
     :stopexec, :saveip, :unsigned_imm, :random, :needpfx,
     :xmmx, :modrmR, :modrmA, :mrmvex
    ].each { |a| @valid_props[a] = true }
  end

  # only most common instructions from the 386 instruction set
  # inexhaustive list :
  # no aaa, arpl, mov crX, call/jmp/ret far, in/out, bts, xchg...
  def init_386_common_only
    init_cpu_constants

    addop_macro1 'adc', 2
    addop_macro1 'add', 0
    addop_macro1 'and', 4, :unsigned_imm
    addop 'bswap', [0x0F, 0xC8], :reg
    addop 'call',  [0xE8], nil, :stopexec, :setip, :i, :saveip
    addop 'call',  [0xFF], 2, :stopexec, :setip, :saveip
    addop('cbw',   [0x98]) { |o| o.props[:opsz] = 16 }
    addop('cwde',  [0x98]) { |o| o.props[:opsz] = 32 }
    addop('cwd',   [0x99]) { |o| o.props[:opsz] = 16 }
    addop('cdq',   [0x99]) { |o| o.props[:opsz] = 32 }
    addop_macro1 'cmp', 7
    addop_macrostr 'cmps',  [0xA6], :stropz
    addop 'dec',   [0x48], :reg
    addop 'dec',   [0xFE], 1,    {:w => [0, 0]}
    addop 'div',   [0xF6], 6,    {:w => [0, 0]}
    addop 'enter', [0xC8], nil, :u16, :u8
    addop 'idiv',  [0xF6], 7,    {:w => [0, 0]}
    addop 'imul',  [0xF6], 5,    {:w => [0, 0]}	# implicit eax, but different semantic from imul eax, ebx (the implicit version updates edx:eax)
    addop 'imul',  [0x0F, 0xAF], :mrm
    addop 'imul',  [0x69], :mrm, {:s => [0, 1]}, :i
    addop 'inc',   [0x40], :reg
    addop 'inc',   [0xFE], 0,    {:w => [0, 0]}
    addop 'int',   [0xCC], nil, :imm_val3, :stopexec
    addop 'int',   [0xCD], nil, :u8
    addop_macrotttn 'j', [0x70], nil, :setip, :i8
    addop_macrotttn('j', [0x70], nil, :setip, :i8) { |o| o.name << '.i8' }
    addop_macrotttn 'j', [0x0F, 0x80], nil, :setip, :i
    addop_macrotttn('j', [0x0F, 0x80], nil, :setip, :i) { |o| o.name << '.i' }
    addop 'jmp',   [0xE9], nil,  {:s => [0, 1]}, :setip, :i,  :stopexec
    addop 'jmp',   [0xFF], 4, :setip, :stopexec
    addop 'lea',   [0x8D], :mrmA
    addop 'leave', [0xC9]
    addop_macrostr 'lods',  [0xAC], :strop
    addop 'loop',  [0xE2], nil, :setip, :i8
    addop 'loopz', [0xE1], nil, :setip, :i8
    addop 'loope', [0xE1], nil, :setip, :i8
    addop 'loopnz',[0xE0], nil, :setip, :i8
    addop 'loopne',[0xE0], nil, :setip, :i8
    addop 'mov',   [0xA0], nil,  {:w => [0, 0], :d => [0, 1]}, :reg_eax, :mrm_imm
    addop('mov',   [0x88], :mrmw,{:d => [0, 1]}) { |o| o.args.reverse! }
    addop 'mov',   [0xB0], :reg, {:w => [0, 3]}, :i, :unsigned_imm
    addop 'mov',   [0xC6], 0,    {:w => [0, 0]}, :i, :unsigned_imm
    addop_macrostr 'movs',  [0xA4], :strop
    addop 'movsx', [0x0F, 0xBE], :mrmw
    addop 'movzx', [0x0F, 0xB6], :mrmw
    addop 'mul',   [0xF6], 4,    {:w => [0, 0]}
    addop 'neg',   [0xF6], 3,    {:w => [0, 0]}
    addop 'nop',   [0x90]
    addop 'not',   [0xF6], 2,    {:w => [0, 0]}
    addop_macro1 'or', 1, :unsigned_imm
    addop 'pop',   [0x58], :reg
    addop 'pop',   [0x8F], 0
    addop 'push',  [0x50], :reg
    addop 'push',  [0xFF], 6
    addop 'push',  [0x68], nil,  {:s => [0, 1]}, :i, :unsigned_imm
    addop 'ret',   [0xC3], nil, :stopexec, :setip
    addop 'ret',   [0xC2], nil, :stopexec, :u16, :setip
    addop_macro3 'rol', 0
    addop_macro3 'ror', 1
    addop_macro3 'sar', 7
    addop_macro1 'sbb', 3
    addop_macrostr 'scas',  [0xAE], :stropz
    addop_macrotttn('set', [0x0F, 0x90], 0) { |o| o.props[:argsz] = 8 }
    addop_macrotttn('set', [0x0F, 0x90], :mrm) { |o| o.props[:argsz] = 8 ; o.args.reverse! }	# :reg field is unused
    addop_macro3 'shl', 4
    addop_macro3 'sal', 6
    addop 'shld',  [0x0F, 0xA4], :mrm, :u8
    addop 'shld',  [0x0F, 0xA5], :mrm, :reg_cl
    addop_macro3 'shr', 5
    addop 'shrd',  [0x0F, 0xAC], :mrm, :u8
    addop 'shrd',  [0x0F, 0xAD], :mrm, :reg_cl
    addop_macrostr 'stos',  [0xAA], :strop
    addop_macro1 'sub', 5
    addop 'test',  [0x84], :mrmw
    addop 'test',  [0xA8], nil,  {:w => [0, 0]}, :reg_eax, :i, :unsigned_imm
    addop 'test',  [0xF6], 0,    {:w => [0, 0]}, :i, :unsigned_imm
    addop 'xchg',  [0x90], :reg, :reg_eax
    addop('xchg',  [0x90], :reg, :reg_eax) { |o| o.args.reverse! }	# xchg eax, ebx == xchg ebx, eax)
    addop 'xchg',  [0x86], :mrmw
    addop('xchg',  [0x86], :mrmw) { |o| o.args.reverse! }
    addop_macro1 'xor', 6, :unsigned_imm
  end

  def init_386_only
    init_cpu_constants

    addop 'aaa',   [0x37]
    addop 'aad',   [0xD5, 0x0A]
    addop 'aam',   [0xD4, 0x0A]
    addop 'aas',   [0x3F]
    addop('arpl',  [0x63], :mrm) { |o| o.props[:argsz] = 16 ; o.args.reverse! }
    addop 'bound', [0x62], :mrmA
    addop 'bsf',   [0x0F, 0xBC], :mrm
    addop 'bsr',   [0x0F, 0xBD], :mrm
    addop_macro2 'bt' , 0
    addop_macro2 'btc', 3
    addop_macro2 'btr', 2
    addop_macro2 'bts', 1
    addop 'call',  [0x9A], nil, :stopexec, :setip, :farptr, :saveip
    addop 'callf', [0x9A], nil, :stopexec, :setip, :farptr, :saveip
    addop 'callf', [0xFF], 3, :stopexec, :setip, :saveip
    addop 'clc',   [0xF8]
    addop 'cld',   [0xFC]
    addop 'cli',   [0xFA]
    addop 'clts',  [0x0F, 0x06]
    addop 'cmc',   [0xF5]
    addop('cmpxchg',[0x0F, 0xB0], :mrmw) { |o| o.args.reverse! }
    addop 'cpuid', [0x0F, 0xA2]
    addop 'daa',   [0x27]
    addop 'das',   [0x2F]
    addop 'hlt',   [0xF4], nil, :stopexec
    addop 'in',    [0xE4], nil,  {:w => [0, 0]}, :reg_eax, :u8
    addop 'in',    [0xE4], nil,  {:w => [0, 0]}, :u8
    addop 'in',    [0xEC], nil,  {:w => [0, 0]}, :reg_eax, :reg_dx
    addop 'in',    [0xEC], nil,  {:w => [0, 0]}, :reg_eax
    addop 'in',    [0xEC], nil,  {:w => [0, 0]}
    addop_macrostr 'ins',   [0x6C], :strop
    addop 'into',  [0xCE]
    addop 'invd',  [0x0F, 0x08]
    addop 'invlpg', [0x0F, 0x01, 7<<3], :modrmA
    addop('iretd', [0xCF], nil, :stopexec, :setip) { |o| o.props[:opsz] = 32 }
    addop_macroret 'iret', [0xCF]
    addop('jcxz',  [0xE3], nil, :setip, :i8) { |o| o.props[:adsz] = 16 }
    addop('jecxz', [0xE3], nil, :setip, :i8) { |o| o.props[:adsz] = 32 }
    addop 'jmp',   [0xEA], nil, :farptr, :setip, :stopexec
    addop 'jmpf',  [0xEA], nil, :farptr, :setip, :stopexec
    addop 'jmpf',  [0xFF], 5, :stopexec, :setip		# reg ?
    addop 'lahf',  [0x9F]
    addop 'lar',   [0x0F, 0x02], :mrm
    addop 'lds',   [0xC5], :mrmA
    addop 'les',   [0xC4], :mrmA
    addop 'lfs',   [0x0F, 0xB4], :mrmA
    addop 'lgs',   [0x0F, 0xB5], :mrmA
    addop 'lgdt',  [0x0F, 0x01], 2, :modrmA
    addop 'lidt',  [0x0F, 0x01, 3<<3], :modrmA
    addop 'lldt',  [0x0F, 0x00], 2, :modrmA
    addop 'lmsw',  [0x0F, 0x01], 6
# prefix	addop 'lock',  [0xF0]
    addop 'lsl',   [0x0F, 0x03], :mrm
    addop 'lss',   [0x0F, 0xB2], :mrmA
    addop 'ltr',   [0x0F, 0x00], 3
    addop 'mov',   [0x0F, 0x20, 0xC0], :reg, {:d => [1, 1], :eeec => [2, 3]}, :eeec
    addop 'mov',   [0x0F, 0x21, 0xC0], :reg, {:d => [1, 1], :eeed => [2, 3]}, :eeed
    addop 'mov',   [0x0F, 0x24, 0xC0], :reg, {:d => [1, 1], :eeet => [2, 3]}, :eeet
    addop 'mov',   [0x8C], 0,    {:d => [0, 1], :seg3 => [1, 3]}, :seg3
    addop 'movbe', [0x0F, 0x38, 0xF0], :mrm, { :d => [2, 0] }
    addop 'out',   [0xE6], nil,  {:w => [0, 0]}, :u8, :reg_eax
    addop 'out',   [0xE6], nil,  {:w => [0, 0]}, :reg_eax, :u8
    addop 'out',   [0xE6], nil,  {:w => [0, 0]}, :u8
    addop 'out',   [0xEE], nil,  {:w => [0, 0]}, :reg_dx, :reg_eax
    addop 'out',   [0xEE], nil,  {:w => [0, 0]}, :reg_eax, :reg_dx
    addop 'out',   [0xEE], nil,  {:w => [0, 0]}, :reg_eax			# implicit arguments
    addop 'out',   [0xEE], nil,  {:w => [0, 0]}
    addop_macrostr 'outs',  [0x6E], :strop
    addop 'pop',   [0x07], nil,  {:seg2A => [0, 3]}, :seg2A
    addop 'pop',   [0x0F, 0x81], nil,  {:seg3A => [1, 3]}, :seg3A
    addop('popa',  [0x61]) { |o| o.props[:opsz] = 16 }
    addop('popad', [0x61]) { |o| o.props[:opsz] = 32 }
    addop('popf',  [0x9D]) { |o| o.props[:opsz] = 16 }
    addop('popfd', [0x9D]) { |o| o.props[:opsz] = 32 }
    addop 'push',  [0x06], nil,  {:seg2 => [0, 3]}, :seg2
    addop 'push',  [0x0F, 0x80], nil,  {:seg3A => [1, 3]}, :seg3A
    addop('pusha', [0x60]) { |o| o.props[:opsz] = 16 }
    addop('pushad',[0x60]) { |o| o.props[:opsz] = 32 }
    addop('pushf', [0x9C]) { |o| o.props[:opsz] = 16 }
    addop('pushfd',[0x9C]) { |o| o.props[:opsz] = 32 }
    addop_macro3 'rcl', 2
    addop_macro3 'rcr', 3
    addop 'rdmsr', [0x0F, 0x32]
    addop 'rdpmc', [0x0F, 0x33]
    addop 'rdtsc', [0x0F, 0x31], nil, :random
    addop_macroret 'retf', [0xCB]
    addop_macroret 'retf', [0xCA], :u16
    addop 'rsm',   [0x0F, 0xAA], nil, :stopexec
    addop 'sahf',  [0x9E]
    addop 'sgdt',  [0x0F, 0x01, 0<<3], :modrmA
    addop 'sidt',  [0x0F, 0x01, 1<<3], :modrmA
    addop 'sldt',  [0x0F, 0x00], 0
    addop 'smsw',  [0x0F, 0x01], 4
    addop 'stc',   [0xF9]
    addop 'std',   [0xFD]
    addop 'sti',   [0xFB]
    addop 'str',   [0x0F, 0x00], 1
    addop 'test',  [0xF6], 1, {:w => [0, 0]}, :i, :unsigned_imm			# undocumented alias to F6/0
    addop 'ud2',   [0x0F, 0x0B]
    addop 'verr',  [0x0F, 0x00], 4
    addop 'verw',  [0x0F, 0x00], 5
    addop 'wait',  [0x9B]
    addop 'wbinvd',[0x0F, 0x09]
    addop 'wrmsr', [0x0F, 0x30]
    addop('xadd',  [0x0F, 0xC0], :mrmw) { |o| o.args.reverse! }
    addop 'xlat',  [0xD7]

# pfx:  addrsz = 0x67, lock = 0xF0, opsz = 0x66, repnz = 0xF2, rep/repz = 0xF3
#	cs/nojmp = 0x2E, ds/jmp = 0x3E, es = 0x26, fs = 0x64, gs = 0x65, ss = 0x36

    # undocumented opcodes
    addop 'aam',   [0xD4], nil, :u8
    addop 'aad',   [0xD5], nil, :u8
    addop 'setalc',[0xD6]
    addop 'salc',  [0xD6]
    addop 'icebp', [0xF1]
    #addop 'loadall',[0x0F, 0x07]	# conflict with syscall
    addop 'ud0',   [0x0F, 0xFF]	# amd
    addop 'ud2',   [0x0F, 0xB9], :mrm
    #addop 'umov',  [0x0F, 0x10], :mrmw, {:d => [1, 1]}	# conflicts with movups/movhlps
  end

  def init_387_only
    init_cpu_constants

    addop 'f2xm1', [0xD9, 0xF0]
    addop 'fabs',  [0xD9, 0xE1]
    addop_macrofpu1 'fadd',  0
    addop 'faddp', [0xDE, 0xC0], :regfp
    addop 'faddp', [0xDE, 0xC1]
    addop('fbld',  [0xDF, 4<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 80 }
    addop('fbstp', [0xDF, 6<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 80 }
    addop 'fchs',  [0xD9, 0xE0], nil, :regfp0
    addop 'fnclex',      [0xDB, 0xE2]
    addop_macrofpu1 'fcom',  2
    addop_macrofpu1 'fcomp', 3
    addop 'fcompp',[0xDE, 0xD9]
    addop 'fcomip',[0xDF, 0xF0], :regfp
    addop 'fcos',  [0xD9, 0xFF], nil, :regfp0
    addop 'fdecstp', [0xD9, 0xF6]
    addop_macrofpu1 'fdiv', 6
    addop_macrofpu1 'fdivr', 7
    addop 'fdivp', [0xDE, 0xF8], :regfp
    addop 'fdivp', [0xDE, 0xF9]
    addop 'fdivrp',[0xDE, 0xF0], :regfp
    addop 'fdivrp',[0xDE, 0xF1]
    addop 'ffree', [0xDD, 0xC0], nil,  {:regfp  => [1, 0]}, :regfp
    addop_macrofpu2 'fiadd', 0
    addop_macrofpu2 'fimul', 1
    addop_macrofpu2 'ficom', 2
    addop_macrofpu2 'ficomp',3
    addop_macrofpu2 'fisub', 4
    addop_macrofpu2 'fisubr',5
    addop_macrofpu2 'fidiv', 6
    addop_macrofpu2 'fidivr',7
    addop 'fincstp', [0xD9, 0xF7]
    addop 'fninit',      [0xDB, 0xE3]
    addop_macrofpu2 'fist', 2, 1
    addop_macrofpu3 'fild', 0
    addop_macrofpu3 'fistp',3
    addop('fld', [0xD9, 0<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 32 }
    addop('fld', [0xDD, 0<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 64 }
    addop('fld', [0xDB, 5<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 80 }
    addop 'fld', [0xD9, 0xC0], :regfp

    addop('fldcw',  [0xD9, 5<<3], :modrmA) { |o| o.props[:argsz] = 16 }
    addop 'fldenv', [0xD9, 4<<3], :modrmA
    addop 'fld1',   [0xD9, 0xE8]
    addop 'fldl2t', [0xD9, 0xE9]
    addop 'fldl2e', [0xD9, 0xEA]
    addop 'fldpi',  [0xD9, 0xEB]
    addop 'fldlg2', [0xD9, 0xEC]
    addop 'fldln2', [0xD9, 0xED]
    addop 'fldz',   [0xD9, 0xEE]
    addop_macrofpu1 'fmul',  1
    addop 'fmulp',  [0xDE, 0xC8], :regfp
    addop 'fmulp',  [0xDE, 0xC9]
    addop 'fnop',   [0xD9, 0xD0]
    addop 'fpatan', [0xD9, 0xF3]
    addop 'fprem',  [0xD9, 0xF8]
    addop 'fprem1', [0xD9, 0xF5]
    addop 'fptan',  [0xD9, 0xF2]
    addop 'frndint',[0xD9, 0xFC]
    addop 'frstor', [0xDD, 4<<3], :modrmA
    addop 'fnsave', [0xDD, 6<<3], :modrmA
    addop('fnstcw', [0xD9, 7<<3], :modrmA) { |o| o.props[:argsz] = 16 }
    addop 'fnstenv',[0xD9, 6<<3], :modrmA
    addop 'fnstsw', [0xDF, 0xE0]
    addop('fnstsw', [0xDD, 7<<3], :modrmA) { |o| o.props[:argsz] = 16 }
    addop 'fscale', [0xD9, 0xFD]
    addop 'fsin',   [0xD9, 0xFE]
    addop 'fsincos',[0xD9, 0xFB]
    addop 'fsqrt',  [0xD9, 0xFA]
    addop('fst',  [0xD9, 2<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 32 }
    addop('fst',  [0xDD, 2<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 64 }
    addop 'fst',  [0xD9, 0xD0], :regfp
    addop('fstp', [0xD9, 3<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 32 }
    addop('fstp', [0xDD, 3<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 64 }
    addop('fstp', [0xDB, 7<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 80 }
    addop 'fstp', [0xDD, 0xD8], :regfp
    addop_macrofpu1 'fsub',  4
    addop 'fsubp',  [0xDE, 0xE8], :regfp
    addop 'fsubp',  [0xDE, 0xE9]
    addop_macrofpu1 'fsubp', 5
    addop 'fsubrp', [0xDE, 0xE0], :regfp
    addop 'fsubrp', [0xDE, 0xE1]
    addop 'ftst',   [0xD9, 0xE4]
    addop 'fucom',  [0xDD, 0xE0], :regfp
    addop 'fucomp', [0xDD, 0xE8], :regfp
    addop 'fucompp',[0xDA, 0xE9]
    addop 'fucomi', [0xDB, 0xE8], :regfp
    addop 'fxam',   [0xD9, 0xE5]
    addop 'fxch',   [0xD9, 0xC8], :regfp
    addop 'fxtract',[0xD9, 0xF4]
    addop 'fyl2x',  [0xD9, 0xF1]
    addop 'fyl2xp1',[0xD9, 0xF9]
    # fwait prefix
    addop 'fclex',  [0x9B, 0xDB, 0xE2]
    addop 'finit',  [0x9B, 0xDB, 0xE3]
    addop 'fsave',  [0x9B, 0xDD, 6<<3], :modrmA
    addop('fstcw',  [0x9B, 0xD9, 7<<3], :modrmA) { |o| o.props[:argsz] = 16 }
    addop 'fstenv', [0x9B, 0xD9, 6<<3], :modrmA
    addop 'fstsw',  [0x9B, 0xDF, 0xE0]
    addop('fstsw',  [0x9B, 0xDD, 7<<3], :modrmA) { |o| o.props[:argsz] = 16 }
    addop 'fwait',  [0x9B]
  end

  def init_486_only
    init_cpu_constants
  end

  def init_pentium_only
    init_cpu_constants

    addop('cmpxchg8b', [0x0F, 0xC7], 1) { |o| o.props[:opsz] = 32 ; o.props[:argsz] = 64 }
    # lock cmpxchg8b eax
    #addop 'f00fbug', [0xF0, 0x0F, 0xC7, 0xC8]

    # mmx
    addop 'emms',  [0x0F, 0x77]
    addop('movd',  [0x0F, 0x6E], :mrmmmx, {:d => [1, 4]}) { |o| o.args = [:modrm, :regmmx] ; o.props[:opsz] = o.props[:argsz] = 32 }
    addop('movq',  [0x0F, 0x6F], :mrmmmx, {:d => [1, 4]}) { |o| o.props[:argsz] = 64 }
    addop 'packssdw', [0x0F, 0x6B], :mrmmmx
    addop 'packsswb', [0x0F, 0x63], :mrmmmx
    addop 'packuswb', [0x0F, 0x67], :mrmmmx
    addop_macrogg 0..2, 'padd',  [0x0F, 0xFC], :mrmmmx
    addop_macrogg 0..1, 'padds', [0x0F, 0xEC], :mrmmmx
    addop_macrogg 0..1, 'paddus',[0x0F, 0xDC], :mrmmmx
    addop 'pand',  [0x0F, 0xDB], :mrmmmx
    addop 'pandn', [0x0F, 0xDF], :mrmmmx
    addop_macrogg 0..2, 'pcmpeq',[0x0F, 0x74], :mrmmmx
    addop_macrogg 0..2, 'pcmpgt',[0x0F, 0x64], :mrmmmx
    addop 'pmaddwd', [0x0F, 0xF5], :mrmmmx
    addop 'pmulhuw', [0x0F, 0xE4], :mrmmmx
    addop 'pmulhw',[0x0F, 0xE5], :mrmmmx
    addop 'pmullw',[0x0F, 0xD5], :mrmmmx
    addop 'por',   [0x0F, 0xEB], :mrmmmx
    [[1..3, 'psll', 3], [1..2, 'psra', 2], [1..3, 'psrl', 1]].each { |ggrng, name, val|
      addop_macrogg ggrng, name, [0x0F, 0xC0 | (val << 4)], :mrmmmx
      addop_macrogg ggrng, name, [0x0F, 0x70, 0xC0 | (val << 4)], nil, {:regmmx => [2, 0]}, :regmmx, :u8
    }
    addop_macrogg 0..2, 'psub',  [0x0F, 0xF8], :mrmmmx
    addop_macrogg 0..1, 'psubs', [0x0F, 0xE8], :mrmmmx
    addop_macrogg 0..1, 'psubus',[0x0F, 0xD8], :mrmmmx
    addop_macrogg 1..3, 'punpckh', [0x0F, 0x68], :mrmmmx
    addop_macrogg 1..3, 'punpckl', [0x0F, 0x60], :mrmmmx
    addop 'pxor',  [0x0F, 0xEF], :mrmmmx
  end

  def init_p6_only
    addop_macrotttn 'cmov', [0x0F, 0x40], :mrm

    %w{b e be u}.each_with_index { |tt, i|
      addop 'fcmov' + tt, [0xDA, 0xC0 | (i << 3)], :regfp
      addop 'fcmovn'+ tt, [0xDB, 0xC0 | (i << 3)], :regfp
    }
    addop 'fcomi', [0xDB, 0xF0], :regfp
    addop('fxrstor', [0x0F, 0xAE, 1<<3], :modrmA) { |o| o.props[:argsz] = 512*8 }
    addop('fxsave',  [0x0F, 0xAE, 0<<3], :modrmA) { |o| o.props[:argsz] = 512*8 }
    addop 'sysenter',[0x0F, 0x34]
    addop 'sysexit', [0x0F, 0x35]

    addop 'syscall', [0x0F, 0x05]	# AMD
    addop_macroret 'sysret', [0x0F, 0x07]	# AMD
  end

  def init_3dnow_only
    init_cpu_constants

    [['pavgusb', 0xBF], ['pfadd', 0x9E], ['pfsub', 0x9A],
     ['pfsubr', 0xAA], ['pfacc', 0xAE], ['pfcmpge', 0x90],
     ['pfcmpgt', 0xA0], ['fpcmpeq', 0xB0], ['pfmin', 0x94],
     ['pfmax', 0xA4], ['pi2fd', 0x0D], ['pf2id', 0x1D],
     ['pfrcp', 0x96], ['pfrsqrt', 0x97], ['pfmul', 0xB4],
     ['pfrcpit1', 0xA6], ['pfrsqit1', 0xA7], ['pfrcpit2', 0xB6],
     ['pmulhrw', 0xB7]].each { |str, bin|
      addop str, [0x0F, 0x0F, bin], :mrmmmx
    }
    # 3dnow prefix fallback
    addop '3dnow', [0x0F, 0x0F], :mrmmmx, :u8

    addop 'femms', [0x0F, 0x0E]
    addop 'prefetch',  [0x0F, 0x0D, 0<<3], :modrmA
    addop 'prefetchw', [0x0F, 0x0D, 1<<3], :modrmA
  end

  def init_sse_only
    init_cpu_constants

    addop_macrossps 'addps', [0x0F, 0x58], :mrmxmm
    addop 'andnps',  [0x0F, 0x55], :mrmxmm
    addop 'andps',   [0x0F, 0x54], :mrmxmm
    addop_macrossps 'cmpps', [0x0F, 0xC2], :mrmxmm, :u8
    addop 'comiss',  [0x0F, 0x2F], :mrmxmm

    addop('cvtpi2ps', [0x0F, 0x2A], :mrmxmm) { |o| o.args[o.args.index(:modrmxmm)] = :modrmmmx }
    addop('cvtps2pi', [0x0F, 0x2D], :mrmmmx) { |o| o.args[o.args.index(:modrmmmx)] = :modrmxmm }
    addop('cvtsi2ss', [0x0F, 0x2A], :mrmxmm) { |o| o.args[o.args.index(:modrmxmm)] = :modrm ; o.props[:needpfx] = 0xF3 }
    addop('cvtss2si', [0x0F, 0x2D], :mrm)    { |o| o.args[o.args.index(:modrm)] = :modrmxmm ; o.props[:needpfx] = 0xF3 }
    addop('cvttps2pi',[0x0F, 0x2C], :mrmmmx) { |o| o.args[o.args.index(:modrmmmx)] = :modrmxmm }
    addop('cvttss2si',[0x0F, 0x2C], :mrm)    { |o| o.args[o.args.index(:modrm)] = :modrmxmm ; o.props[:needpfx] = 0xF3 }

    addop_macrossps 'divps', [0x0F, 0x5E], :mrmxmm
    addop 'ldmxcsr', [0x0F, 0xAE, 2<<3], :modrmA
    addop_macrossps 'maxps', [0x0F, 0x5F], :mrmxmm
    addop_macrossps 'minps', [0x0F, 0x5D], :mrmxmm
    addop 'movaps',  [0x0F, 0x28], :mrmxmm, {:d => [1, 0]}
    addop 'movhlps', [0x0F, 0x12], :mrmxmm, :modrmR
    addop 'movlps',  [0x0F, 0x12], :mrmxmm, {:d => [1, 0]}, :modrmA
    addop 'movlhps', [0x0F, 0x16], :mrmxmm, :modrmR
    addop 'movhps',  [0x0F, 0x16], :mrmxmm, {:d => [1, 0]}, :modrmA
    addop 'movmskps',[0x0F, 0x50, 0xC0], nil, {:reg => [2, 3], :regxmm => [2, 0]}, :regxmm, :reg
    addop('movss',   [0x0F, 0x10], :mrmxmm, {:d => [1, 0]}) { |o| o.props[:needpfx] = 0xF3 }
    addop 'movups',  [0x0F, 0x10], :mrmxmm, {:d => [1, 0]}
    addop_macrossps 'mulps', [0x0F, 0x59], :mrmxmm
    addop 'orps',    [0x0F, 0x56], :mrmxmm
    addop_macrossps 'rcpps',  [0x0F, 0x53], :mrmxmm
    addop_macrossps 'rsqrtps',[0x0F, 0x52], :mrmxmm
    addop 'shufps',  [0x0F, 0xC6], :mrmxmm, :u8
    addop_macrossps 'sqrtps', [0x0F, 0x51], :mrmxmm
    addop 'stmxcsr', [0x0F, 0xAE, 3<<3], :modrmA
    addop_macrossps 'subps', [0x0F, 0x5C], :mrmxmm
    addop 'ucomiss', [0x0F, 0x2E], :mrmxmm
    addop 'unpckhps',[0x0F, 0x15], :mrmxmm
    addop 'unpcklps',[0x0F, 0x14], :mrmxmm
    addop 'xorps',   [0x0F, 0x57], :mrmxmm

    # integer instrs, mmx only
    addop 'pavgb',   [0x0F, 0xE0], :mrmmmx
    addop 'pavgw',   [0x0F, 0xE3], :mrmmmx
    addop 'pextrw',  [0x0F, 0xC5, 0xC0], nil, {:reg => [2, 3], :regmmx => [2, 0]}, :reg, :regmmx, :u8
    addop 'pinsrw',  [0x0F, 0xC4, 0x00], nil, {:modrm => [2, 0], :regmmx => [2, 3]}, :modrm, :regmmx, :u8
    addop 'pmaxsw',  [0x0F, 0xEE], :mrmmmx
    addop 'pmaxub',  [0x0F, 0xDE], :mrmmmx
    addop 'pminsw',  [0x0F, 0xEA], :mrmmmx
    addop 'pminub',  [0x0F, 0xDA], :mrmmmx
    addop 'pmovmskb',[0x0F, 0xD7, 0xC0], nil, {:reg => [2, 3], :regmmx => [2, 0]}, :reg, :regmmx
    addop 'psadbw',  [0x0F, 0xF6], :mrmmmx
    addop 'pshufw',  [0x0F, 0x70], :mrmmmx, :u8

    addop 'maskmovq',[0x0F, 0xF7], :mrmmmx, :modrmR
    addop('movntq',  [0x0F, 0xE7], :mrmmmx) { |o| o.args.reverse! }
    addop('movntps', [0x0F, 0x2B], :mrmxmm) { |o| o.args.reverse! }
    addop 'prefetcht0', [0x0F, 0x18, 1<<3], :modrmA
    addop 'prefetcht1', [0x0F, 0x18, 2<<3], :modrmA
    addop 'prefetcht2', [0x0F, 0x18, 3<<3], :modrmA
    addop 'prefetchnta',[0x0F, 0x18, 0<<3], :modrmA
    addop 'sfence',  [0x0F, 0xAE, 0xF8]

    # the whole row of prefetch is actually nops
    addop 'nop', [0x0F, 0x1C], :mrmw, :d => [1, 1]	# incl. official version = 0f1f mrm
    addop 'nop_8', [0x0F, 0x18], :mrmw, :d => [1, 1]
    addop 'nop_d', [0x0F, 0x0D], :mrm
    addop 'nop', [0x0F, 0x1C], 0	# official asm syntax is 'nop [eax]'
  end

  def init_sse2_only
    init_cpu_constants

    @opcode_list.each { |o| o.props[:xmmx] = true if o.fields[:regmmx] and o.name !~ /^(?:mov(?:nt)?q|pshufw|cvt.*)$/ }

    # mirror of the init_sse part
    addop_macrosdpd 'addpd', [0x0F, 0x58], :mrmxmm
    addop('andnpd',  [0x0F, 0x55], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('andpd',   [0x0F, 0x54], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop_macrosdpd 'cmppd', [0x0F, 0xC2], :mrmxmm, :u8
    addop('comisd',  [0x0F, 0x2F], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }

    addop('cvtpi2pd', [0x0F, 0x2A], :mrmxmm) { |o| o.args[o.args.index(:modrmxmm)] = :modrmmmx ; o.props[:needpfx] = 0x66 }
    addop('cvtpd2pi', [0x0F, 0x2D], :mrmmmx) { |o| o.args[o.args.index(:modrmmmx)] = :modrmxmm ; o.props[:needpfx] = 0x66 }
    addop('cvtsi2sd', [0x0F, 0x2A], :mrmxmm) { |o| o.args[o.args.index(:modrmxmm)] = :modrm    ; o.props[:needpfx] = 0xF2 }
    addop('cvtsd2si', [0x0F, 0x2D], :mrm   ) { |o| o.args[o.args.index(:modrm   )] = :modrmxmm ; o.props[:needpfx] = 0xF2 }
    addop('cvttpd2pi',[0x0F, 0x2C], :mrmmmx) { |o| o.args[o.args.index(:modrmmmx)] = :modrmxmm ; o.props[:needpfx] = 0x66 }
    addop('cvttsd2si',[0x0F, 0x2C], :mrm   ) { |o| o.args[o.args.index(:modrm   )] = :modrmxmm ; o.props[:needpfx] = 0xF2 }

    addop('cvtpd2ps', [0x0F, 0x5A], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('cvtps2pd', [0x0F, 0x5A], :mrmxmm)
    addop('cvtsd2ss', [0x0F, 0x5A], :mrmxmm) { |o| o.props[:needpfx] = 0xF2 }
    addop('cvtss2sd', [0x0F, 0x5A], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }

    addop('cvtpd2dq', [0x0F, 0xE6], :mrmxmm) { |o| o.props[:needpfx] = 0xF2 }
    addop('cvttpd2dq',[0x0F, 0xE6], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('cvtdq2pd', [0x0F, 0xE6], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }
    addop('cvtps2dq', [0x0F, 0x5B], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('cvttps2dq',[0x0F, 0x5B], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }
    addop('cvtdq2ps', [0x0F, 0x5B], :mrmxmm)

    addop_macrosdpd 'divpd', [0x0F, 0x5E], :mrmxmm
    addop_macrosdpd 'maxpd', [0x0F, 0x5F], :mrmxmm
    addop_macrosdpd 'minpd', [0x0F, 0x5D], :mrmxmm
    addop('movapd',  [0x0F, 0x28], :mrmxmm, {:d => [1, 0]}) { |o| o.props[:needpfx] = 0x66 }

    addop('movlpd',  [0x0F, 0x12], :mrmxmm, {:d => [1, 0]}) { |o| o.props[:needpfx] = 0x66 }
    addop('movhpd',  [0x0F, 0x16], :mrmxmm, {:d => [1, 0]}) { |o| o.props[:needpfx] = 0x66 }

    addop('movmskpd',[0x0F, 0x50, 0xC0], nil, {:reg => [2, 3], :regxmm => [2, 0]}, :regxmm, :reg) { |o| o.props[:needpfx] = 0x66 }
    addop('movsd',   [0x0F, 0x10], :mrmxmm, {:d => [1, 0]}) { |o| o.props[:needpfx] = 0xF2 }
    addop('movupd',  [0x0F, 0x10], :mrmxmm, {:d => [1, 0]}) { |o| o.props[:needpfx] = 0x66 }
    addop_macrosdpd 'mulpd', [0x0F, 0x59], :mrmxmm
    addop('orpd',    [0x0F, 0x56], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('shufpd',  [0x0F, 0xC6], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop_macrosdpd 'sqrtpd', [0x0F, 0x51], :mrmxmm
    addop_macrosdpd 'subpd', [0x0F, 0x5C], :mrmxmm
    addop('ucomisd', [0x0F, 0x2E], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('unpckhpd',[0x0F, 0x15], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('unpcklpd',[0x0F, 0x14], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('xorpd',   [0x0F, 0x57], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }

    addop('movdqa',  [0x0F, 0x6F], :mrmxmm, {:d => [1, 4]}) { |o| o.props[:needpfx] = 0x66 }
    addop('movdqu',  [0x0F, 0x6F], :mrmxmm, {:d => [1, 4]}) { |o| o.props[:needpfx] = 0xF3 }
    addop('movq2dq', [0x0F, 0xD6], :mrmxmm, :modrmR) { |o| o.args[o.args.index(:modrmxmm)] = :modrmmmx ; o.props[:needpfx] = 0xF3 }
    addop('movdq2q', [0x0F, 0xD6], :mrmmmx, :modrmR) { |o| o.args[o.args.index(:modrmmmx)] = :modrmxmm ; o.props[:needpfx] = 0xF2 }
    addop('movq',    [0x0F, 0x7E], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 ; o.props[:argsz] = 128 }
    addop('movq',    [0x0F, 0xD6], :mrmxmm) { |o| o.args.reverse! ; o.props[:needpfx] = 0x66 ; o.props[:argsz] = 128 }

    addop 'paddq',   [0x0F, 0xD4], :mrmmmx, :xmmx
    addop 'pmuludq', [0x0F, 0xF4], :mrmmmx, :xmmx
    addop('pshuflw', [0x0F, 0x70], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0xF2 }
    addop('pshufhw', [0x0F, 0x70], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0xF3 }
    addop('pshufd',  [0x0F, 0x70], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('pslldq',  [0x0F, 0x73, 0xF8], nil, {:regxmm => [2, 0]}, :regxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('psrldq',  [0x0F, 0x73, 0xD8], nil, {:regxmm => [2, 0]}, :regxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop 'psubq',   [0x0F, 0xFB], :mrmmmx, :xmmx
    addop('punpckhqdq', [0x0F, 0x6D], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('punpcklqdq', [0x0F, 0x6C], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }

    addop('clflush', [0x0F, 0xAE, 7<<3], :modrmA) { |o| o.props[:argsz] = 8 }
    addop('maskmovdqu', [0x0F, 0xF7], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('movntpd', [0x0F, 0x2B], :mrmxmm) { |o| o.args.reverse! ; o.props[:needpfx] = 0x66 }
    addop('movntdq', [0x0F, 0xE7], :mrmxmm) { |o| o.args.reverse! ; o.props[:needpfx] = 0x66 }
    addop('movnti',  [0x0F, 0xC3], :mrm) { |o| o.args.reverse! }
    addop('pause',   [0x90]) { |o| o.props[:needpfx] = 0xF3 }
    addop 'lfence',  [0x0F, 0xAE, 0xE8]
    addop 'mfence',  [0x0F, 0xAE, 0xF0]
  end

  def init_sse3_only
    init_cpu_constants

    addop('addsubpd', [0x0F, 0xD0], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('addsubps', [0x0F, 0xD0], :mrmxmm) { |o| o.props[:needpfx] = 0xF2 }
    addop('haddpd',   [0x0F, 0x7C], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('haddps',   [0x0F, 0x7C], :mrmxmm) { |o| o.props[:needpfx] = 0xF2 }
    addop('hsubpd',   [0x0F, 0x7D], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('hsubps',   [0x0F, 0x7D], :mrmxmm) { |o| o.props[:needpfx] = 0xF2 }

    addop 'monitor',  [0x0F, 0x01, 0xC8]
    addop 'mwait',    [0x0F, 0x01, 0xC9]

    addop('fisttp',   [0xDF, 1<<3], :modrmA) { |o| o.props[:argsz] = 16 }
    addop('fisttp',   [0xDB, 1<<3], :modrmA) { |o| o.props[:argsz] = 32 }
    addop('fisttp',   [0xDD, 1<<3], :modrmA) { |o| o.props[:argsz] = 64 }
    addop('lddqu',    [0x0F, 0xF0], :mrmxmm, :modrmA) { |o| o.args[o.args.index(:modrmxmm)] = :modrm ; o.props[:needpfx] = 0xF2 }
    addop('movddup',  [0x0F, 0x12], :mrmxmm) { |o| o.props[:needpfx] = 0xF2 }
    addop('movshdup', [0x0F, 0x16], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }
    addop('movsldup', [0x0F, 0x12], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }
  end

  def init_ssse3_only
    init_cpu_constants

    addop_macrogg 0..2, 'pabs', [0x0F, 0x38, 0x1C], :mrmmmx, :xmmx
    addop 'palignr',  [0x0F, 0x3A, 0x0F], :mrmmmx, :u8, :xmmx
    addop 'phaddd',   [0x0F, 0x38, 0x02], :mrmmmx, :xmmx
    addop 'phaddsw',  [0x0F, 0x38, 0x03], :mrmmmx, :xmmx
    addop 'phaddw',   [0x0F, 0x38, 0x01], :mrmmmx, :xmmx
    addop 'phsubd',   [0x0F, 0x38, 0x06], :mrmmmx, :xmmx
    addop 'phsubsw',  [0x0F, 0x38, 0x07], :mrmmmx, :xmmx
    addop 'phsubw',   [0x0F, 0x38, 0x05], :mrmmmx, :xmmx
    addop 'pmaddubsw',[0x0F, 0x38, 0x04], :mrmmmx, :xmmx
    addop 'pmulhrsw', [0x0F, 0x38, 0x0B], :mrmmmx, :xmmx
    addop 'pshufb',   [0x0F, 0x38, 0x00], :mrmmmx, :xmmx
    addop_macrogg 0..2, 'psignb', [0x0F, 0x38, 0x80], :mrmmmx, :xmmx
  end

  def init_aesni_only
    init_cpu_constants

    addop('aesdec',    [0x0F, 0x38, 0xDE], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('aesdeclast',[0x0F, 0x38, 0xDF], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('aesenc',    [0x0F, 0x38, 0xDC], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('aesenclast',[0x0F, 0x38, 0xDD], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('aesimc',    [0x0F, 0x38, 0xDB], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('aeskeygenassist', [0x0F, 0x3A, 0xDF], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }

    addop('pclmulqdq', [0x0F, 0x3A, 0x44], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
  end

  def init_vmx_only
    init_cpu_constants

    addop 'vmcall',   [0x0F, 0x01, 0xC1]
    addop 'vmlaunch', [0x0F, 0x01, 0xC2]
    addop 'vmresume', [0x0F, 0x01, 0xC3]
    addop 'vmxoff',   [0x0F, 0x01, 0xC4]
    addop 'vmread',   [0x0F, 0x78], :mrm
    addop 'vmwrite',  [0x0F, 0x79], :mrm
    addop('vmclear',  [0x0F, 0xC7, 6<<3], :modrmA) { |o| o.props[:argsz] = 64 ; o.props[:needpfx] = 0x66 }
    addop('vmxon',    [0x0F, 0xC7, 6<<3], :modrmA) { |o| o.props[:argsz] = 64 ; o.props[:needpfx] = 0xF3 }
    addop('vmptrld',  [0x0F, 0xC7, 6<<3], :modrmA) { |o| o.props[:argsz] = 64 }
    addop('vmptrrst', [0x0F, 0xC7, 7<<3], :modrmA) { |o| o.props[:argsz] = 64 }
    addop('invept',   [0x0F, 0x38, 0x80], :mrmA) { |o| o.props[:needpfx] = 0x66 }
    addop('invvpid',  [0x0F, 0x38, 0x81], :mrmA) { |o| o.props[:needpfx] = 0x66 }

    addop 'getsec',   [0x0F, 0x37]

    addop 'xgetbv', [0x0F, 0x01, 0xD0]
    addop 'xsetbv', [0x0F, 0x01, 0xD1]
    addop 'rdtscp', [0x0F, 0x01, 0xF9]
    addop 'xrstor', [0x0F, 0xAE, 5<<3], :modrmA
    addop 'xsave',  [0x0F, 0xAE, 4<<3], :modrmA
  end

  def init_sse41_only
    init_cpu_constants

    addop('blendpd',  [0x0F, 0x3A, 0x0D], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('blendps',  [0x0F, 0x3A, 0x0C], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('blendvpd', [0x0F, 0x38, 0x15], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('blendvps', [0x0F, 0x38, 0x14], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('dppd',     [0x0F, 0x3A, 0x41], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('dpps',     [0x0F, 0x3A, 0x40], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('extractps',[0x0F, 0x3A, 0x17], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('insertps', [0x0F, 0x3A, 0x21], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('movntdqa', [0x0F, 0x38, 0x2A], :mrmxmm, :modrmA) { |o| o.props[:needpfx] = 0x66 }
    addop('mpsadbw',  [0x0F, 0x3A, 0x42], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('packusdw', [0x0F, 0x38, 0x2B], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pblendvb', [0x0F, 0x38, 0x10], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pblendw',  [0x0F, 0x3A, 0x1E], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpeqq',  [0x0F, 0x38, 0x29], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pextrb', [0x0F, 0x3A, 0x14], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:argsz] = 8 }
    addop('pextrw', [0x0F, 0x3A, 0x15], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:argsz] = 16 }
    addop('pextrd', [0x0F, 0x3A, 0x16], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:argsz] = 32 }
    addop('pinsrb', [0x0F, 0x3A, 0x20], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:argsz] = 8 }
    addop('pinsrw', [0x0F, 0x3A, 0x21], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:argsz] = 16 }
    addop('pinsrd', [0x0F, 0x3A, 0x22], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:argsz] = 32 }
    addop('phminposuw', [0x0F, 0x38, 0x41], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pminsb', [0x0F, 0x38, 0x38], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pminsd', [0x0F, 0x38, 0x39], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pminuw', [0x0F, 0x38, 0x3A], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pminud', [0x0F, 0x38, 0x3B], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmaxsb', [0x0F, 0x38, 0x3C], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmaxsd', [0x0F, 0x38, 0x3D], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmaxuw', [0x0F, 0x38, 0x3E], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmaxud', [0x0F, 0x38, 0x3F], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }

    addop('pmovsxbw', [0x0F, 0x38, 0x20], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovsxbd', [0x0F, 0x38, 0x21], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovsxbq', [0x0F, 0x38, 0x22], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovsxwd', [0x0F, 0x38, 0x23], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovsxwq', [0x0F, 0x38, 0x24], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovsxdq', [0x0F, 0x38, 0x25], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovzxbw', [0x0F, 0x38, 0x30], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovzxbd', [0x0F, 0x38, 0x31], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovzxbq', [0x0F, 0x38, 0x32], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovzxwd', [0x0F, 0x38, 0x33], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovzxwq', [0x0F, 0x38, 0x34], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmovzxdq', [0x0F, 0x38, 0x35], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }

    addop('pmuldq',  [0x0F, 0x38, 0x28], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('pmulld',  [0x0F, 0x38, 0x40], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('ptest',   [0x0F, 0x38, 0x17], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('roundps', [0x0F, 0x3A, 0x08], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('roundpd', [0x0F, 0x3A, 0x09], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('roundss', [0x0F, 0x3A, 0x0A], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
    addop('roundsd', [0x0F, 0x3A, 0x0B], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66 }
  end

  def init_sse42_only
    init_cpu_constants

    addop('crc32', [0x0F, 0x38, 0xF0], :mrmw) { |o| o.props[:needpfx] = 0xF2 }
    addop('pcmpestrm', [0x0F, 0x3A, 0x60], :mrmxmm, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpestri', [0x0F, 0x3A, 0x61], :mrmxmm, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpistrm', [0x0F, 0x3A, 0x62], :mrmxmm, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpistri', [0x0F, 0x3A, 0x63], :mrmxmm, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpgtq', [0x0F, 0x38, 0x37], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('popcnt', [0x0F, 0xB8], :mrm) { |o| o.props[:needpfx] = 0xF3 }
  end

  def init_avx_only
    init_cpu_constants

    add128 = {}
    add256 = {}
    %w[movss movsd movlhps movhpd movhlps
       cvtsi2ss cvtsi2sd sqrtss sqrtsd rsqrtss rcpss
       addss addsd mulss mulsd cvtss2sd cvtsd2ss subss subsd
       minss minsd divss divsd maxss maxsd
       punpcklb punpcklw punpckld packsswb pcmpgtb pcmpgtw pcmpgtd packuswb
       punpckhb punpckhw punpckhd packssdw punpcklq punpckhq
       pcmpeqb pcmpeqw pcmpeqd ldmxcsr stmxcsr
       cmpss cmpsd paddq pmullw psubusb psubusw pminub
       pand paddusb paddusw pmaxub pandn pavgb pavgw
       pmulhuw pmulhw psubsb psubsw pminsw por paddsb paddsw pmaxsw pxor
       pmuludq pmaddwd psadbw
       psubb psubw psubd psubq paddb paddw paddd
       phaddw phaddsw phaddd phsubw phsubsw phsubd
       pmaddubsw palignr pshufb pmulhrsw psignb psignw psignd
       dppd insertps mpsadbw packusdw pblendw pcmpeqq
       pinsrb pinsrw pinsrd pinsrq
       pmaxsb pmaxsd pmaxud pmaxuw pminsb pminsd pminud pminuw
       pmuldq pmulld roundsd roundss pcmpgtq
       aesdec aesdeclast aesenc aesenclast
       pclmulqdq punpcklbw punpcklwd punpckldq punpckhbw punpckhwd
       punpckhdq punpcklqdq punpckhqdq].each { |n| add128[n] = true }

    %w[movups movupd movddup movsldup
       unpcklps unpcklpd unpckhps unpckhpd
       movaps movshdup movapd movntps movntpd movmskps movmskpd
       sqrtps sqrtpd rsqrtps rcpps andps andpd andnps andnpd
       orps orpd xorps xorpd addps addpd mulps mulpd
       cvtps2pd cvtpd2ps cvtdq2ps cvtps2dq cvttps2dq
       subps subpd minps minpd divps divpd maxps maxpd
       movdqa movdqu haddpd haddps hsubpd hsubps
       cmpps cmppd shufps shufpd addsubpd addsubps
       cvtpd2dq cvttpd2dq cvtdq2pd movntdq lddqu
       blendps blendpd blendvps blendvpd dpps ptest
       roundpd roundps].each { |n| add128[n] = add256[n] = true }

    varg = Hash.new(1)
    %w[pabsb pabsw pabsd pmovmskb pshufd pshufhw pshuflw movntdqa
       pmovsxbw pmovsxbd pmovsxbq pmovsxwd pmovsxwq pmovsxdq
       pmovzxbw pmovzxbd pmovzxbq pmovzxwd pmovzxwq pmovzxdq
       aesimc aeskeygenassist lddqu maskmovdqu movapd movaps
       pcmpestri pcmpestrm pcmpistri pcmpistrm phminposuw
       cvtpd2dq cvttpd2dq cvtdq2pd cvtps2pd cvtpd2ps cvtdq2ps cvtps2dq
       cvttps2dq movd movq movddup movdqa movdqu movmskps movmskpd
       movntdq movntps movntpd movshdup movsldup movups movupd
       pextrb pextrw pextrd pextrq ptest rcpps roundps roundpd
       extractps sqrtps sqrtpd comiss comisd ucomiss ucomisd
       cvttss2si cvttsd2si cvtss2si cvtsd2si
    ].each { |n| add128[n] = true ; varg[n] = nil }

    cvtarg128 = {	:regmmx => :regxmm, :modrmmmx => :modrmxmm }
    cvtarg256 = {	:regmmx => :regymm, :modrmmmx => :modrmymm,
        :regxmm => :regymm, :modrmxmm => :modrmymm }

    # autopromote old sseX opcodes
    @opcode_list.each { |o|
      next if o.bin[0] != 0x0F or not add128[o.name]	# rep cmpsd / movsd

      mm = (o.bin[1] == 0x38 ? 0x0F38 : o.bin[1] == 0x3A ? 0x0F3A : 0x0F)
      pp = o.props[:needpfx]
      pp = 0x66 if o.props[:xmmx]
      fpxlen = (mm == 0x0F ? 1 : 2)

      addop_vex('v' + o.name, [varg[o.name], 128, pp, mm], o.bin[fpxlen], nil, *o.args.map { |oa| cvtarg128[oa] || oa }) { |oo|
        oo.bin += [o.bin[fpxlen+1]] if o.bin[fpxlen+1]
        dbinlen = o.bin.length - oo.bin.length
        o.fields.each { |k, v| oo.fields[cvtarg128[k] || k] = [v[0]-dbinlen, v[1]] }
        o.props.each  { |k, v| oo.props[k] = v if k != :xmmx and k != :needpfx }
      }

      next if not add256[o.name]
      addop_vex('v' + o.name, [varg[o.name], 256, pp, mm], o.bin[fpxlen], nil, *o.args.map { |oa| cvtarg256[oa] || oa }) { |oo|
        oo.bin += [o.bin[fpxlen+1]] if o.bin[fpxlen+1]
        dbinlen = o.bin.length - oo.bin.length
        o.fields.each { |k, v| oo.fields[cvtarg256[k] || k] = [v[0]-dbinlen, v[1]] }
        o.props.each  { |k, v| oo.props[k] = v if k != :xmmx and k != :needpfx }
      }
    }

    # sse promotion, special cases
    addop_vex 'vpblendvb', [1, 128, 0x66, 0x0F3A, 0], 0x4C, :mrmxmm, :i4xmm
    addop_vex 'vpsllw', [1, 128, 0x66, 0x0F], 0xF1, :mrmxmm
    addop_vex('vpsllw', [0, 128, 0x66, 0x0F], 0x71, 6, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex 'vpslld', [1, 128, 0x66, 0x0F], 0xF2, :mrmxmm
    addop_vex('vpslld', [0, 128, 0x66, 0x0F], 0x72, 6, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex 'vpsllq', [1, 128, 0x66, 0x0F], 0xF3, :mrmxmm
    addop_vex('vpsllq', [0, 128, 0x66, 0x0F], 0x73, 6, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex('vpslldq',[0, 128, 0x66, 0x0F], 0x73, 7, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex 'vpsraw', [1, 128, 0x66, 0x0F], 0xE1, :mrmxmm
    addop_vex('vpsraw', [0, 128, 0x66, 0x0F], 0x71, 4, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex 'vpsrad', [1, 128, 0x66, 0x0F], 0xE2, :mrmxmm
    addop_vex('vpsrad', [0, 128, 0x66, 0x0F], 0x72, 4, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex 'vpsrlw', [1, 128, 0x66, 0x0F], 0xD1, :mrmxmm
    addop_vex('vpsrlw', [0, 128, 0x66, 0x0F], 0x71, 2, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex 'vpsrld', [1, 128, 0x66, 0x0F], 0xD2, :mrmxmm
    addop_vex('vpsrld', [0, 128, 0x66, 0x0F], 0x72, 2, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex 'vpsrlq', [1, 128, 0x66, 0x0F], 0xD3, :mrmxmm
    addop_vex('vpsrlq', [0, 128, 0x66, 0x0F], 0x73, 2, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }
    addop_vex('vpsrldq',[0, 128, 0x66, 0x0F], 0x73, 3, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmxmm }

    # dst==mem => no vreg
    addop_vex 'vmovhps', [1,   128, nil,  0x0F], 0x16, :mrmxmm, :modrmA
    addop_vex('vmovhps', [nil, 128, nil,  0x0F], 0x17, :mrmxmm, :modrmA) { |o| o.args.reverse! }
    addop_vex 'vmovlpd', [1,   128, 0x66, 0x0F], 0x12, :mrmxmm, :modrmA
    addop_vex('vmovlpd', [nil, 128, 0x66, 0x0F], 0x13, :mrmxmm, :modrmA) { |o| o.args.reverse! }
    addop_vex 'vmovlps', [1,   128, nil,  0x0F], 0x12, :mrmxmm, :modrmA
    addop_vex('vmovlps', [nil, 128, nil,  0x0F], 0x13, :mrmxmm, :modrmA) { |o| o.args.reverse! }

    addop_vex 'vbroadcastss', [nil, 128, 0x66, 0x0F38, 0], 0x18, :mrmxmm, :modrmA
    addop_vex 'vbroadcastss', [nil, 256, 0x66, 0x0F38, 0], 0x18, :mrmymm, :modrmA
    addop_vex 'vbroadcastsd', [nil, 256, 0x66, 0x0F38, 0], 0x19, :mrmymm, :modrmA
    addop_vex 'vbroadcastf128', [nil, 256, 0x66, 0x0F38, 0], 0x1A, :mrmymm, :modrmA

    # general-purpose register operations
    addop_vex 'andn', [1, :vexvreg, 128, nil, 0x0F38], 0xF2, :mrm
    addop_vex 'bextr', [2, :vexvreg, 128, nil, 0x0F38], 0xF7, :mrm
    addop_vex 'blsi', [0, :vexvreg, 128, nil, 0x0F38], 0xF3, 3
    addop_vex 'blsmsk', [0, :vexvreg, 128, nil, 0x0F38], 0xF3, 2
    addop_vex 'blsr', [0, :vexvreg, 128, nil, 0x0F38], 0xF3, 1
    addop_vex 'bzhi', [2, :vexvreg, 128, nil, 0x0F38], 0xF5, :mrm
    addop('lzcnt', [0x0F, 0xBD], :mrm) { |o| o.props[:needpfx] = 0xF3 }
    addop_vex 'mulx', [1, :vexvreg, 128, 0xF2, 0x0F38], 0xF6, :mrm
    addop_vex 'pdep', [1, :vexvreg, 128, 0xF2, 0x0F38], 0xF5, :mrm
    addop_vex 'pext', [1, :vexvreg, 128, 0xF3, 0x0F38], 0xF5, :mrm
    addop_vex 'rorx', [nil, 128, 0xF2, 0x0F3A], 0xF0, :mrm, :u8
    addop_vex 'sarx', [2, :vexvreg, 128, 0xF3, 0x0F38], 0xF7, :mrm
    addop_vex 'shrx', [2, :vexvreg, 128, 0xF2, 0x0F38], 0xF7, :mrm
    addop_vex 'shlx', [2, :vexvreg, 128, 0x66, 0x0F38], 0xF7, :mrm
    addop('tzcnt', [0x0F, 0xBC], :mrm) { |o| o.props[:needpfx] = 0xF3 }
    addop('invpcid', [0x0F, 0x38, 0x82], :mrm) { |o| o.props[:needpfx] = 0x66 }
    addop 'rdrand', [0x0F, 0xC7], 6, :modrmR
    addop 'rdseed', [0x0F, 0xC7], 7, :modrmR
    addop('adcx', [0x0F, 0x38, 0xF6], :mrm) { |o| o.props[:needpfx] = 0x66 }
    addop('adox', [0x0F, 0x38, 0xF6], :mrm) { |o| o.props[:needpfx] = 0xF3 }

    # fp16
    addop_vex 'vcvtph2ps', [nil, 128, 0x66, 0x0F38, 0], 0x13, :mrmxmm
    addop_vex 'vcvtph2ps', [nil, 256, 0x66, 0x0F38, 0], 0x13, :mrmymm
    addop_vex('vcvtps2ph', [nil, 128, 0x66, 0x0F3A, 0], 0x1D, :mrmxmm, :u8) { |o| o.args.reverse! }
    addop_vex('vcvtps2ph', [nil, 256, 0x66, 0x0F3A, 0], 0x1D, :mrmymm, :u8) { |o| o.args.reverse! }

    # TSE
    addop 'xabort', [0xC6, 0xF8], nil, :i8	# may :stopexec
    addop 'xbegin', [0xC7, 0xF8], nil, :i	# may :setip: xabortreturns to $_(xbegin) + off
    addop 'xend',   [0x0F, 0x01, 0xD5]
    addop 'xtest',  [0x0F, 0x01, 0xD6]

    # SMAP
    addop 'clac',  [0x0F, 0x01, 0xCA]
    addop 'stac',  [0x0F, 0x01, 0xCB]
  end

  def init_avx2_only
    init_cpu_constants

    add256 = {}
    %w[packsswb pcmpgtb pcmpgtw pcmpgtd packuswb packssdw
       pcmpeqb pcmpeqw pcmpeqd paddq pmullw psubusb psubusw
       pminub pand paddusb paddusw pmaxub pandn pavgb pavgw
       pmulhuw pmulhw psubsb psubsw pminsw por paddsb paddsw
       pmaxsw pxor pmuludq pmaddwd psadbw
       psubb psubw psubd psubq paddb paddw paddd
       phaddw phaddsw phaddd phsubw phsubsw phsubd
       pmaddubsw palignr pshufb pmulhrsw psignb psignw psignd
       mpsadbw packusdw pblendw pcmpeqq
       pmaxsb pmaxsd pmaxud pmaxuw pminsb pminsd pminud pminuw
       pmuldq pmulld pcmpgtq punpcklbw punpcklwd punpckldq
       punpckhbw punpckhwd punpckhdq punpcklqdq punpckhqdq
    ].each { |n| add256[n] = true }

    varg = Hash.new(1)
    %w[pabsb pabsw pabsd pmovmskb pshufd pshufhw pshuflw movntdqa
       pmovsxbw pmovsxbd pmovsxbq pmovsxwd pmovsxwq pmovsxdq
       pmovzxbw pmovzxbd pmovzxbq pmovzxwd pmovzxwq pmovzxdq
       maskmovdqu].each { |n| add256[n] = true ; varg[n] = nil }

    cvtarg256 = {	:regmmx => :regymm, :modrmmmx => :modrmymm,
        :regxmm => :regymm, :modrmxmm => :modrmymm }

    # autopromote old sseX opcodes
    @opcode_list.each { |o|
      next if o.bin[0] != 0x0F or not add256[o.name]

      mm = (o.bin[1] == 0x38 ? 0x0F38 : o.bin[1] == 0x3A ? 0x0F3A : 0x0F)
      pp = o.props[:needpfx]
      pp = 0x66 if o.props[:xmmx]
      fpxlen = (mm == 0x0F ? 1 : 2)

      addop_vex('v' + o.name, [varg[o.name], 256, pp, mm], o.bin[fpxlen], nil, *o.args.map { |oa| cvtarg256[oa] || oa }) { |oo|
        oo.bin += [o.bin[fpxlen+1]] if o.bin[fpxlen+1]
        dbinlen = o.bin.length - oo.bin.length
        o.fields.each { |k, v| oo.fields[cvtarg256[k] || k] = [v[0]-dbinlen, v[1]] }
        o.props.each  { |k, v| oo.props[k] = v if k != :xmmx and k != :needpfx }
      }
    }

    # promote special cases
    addop_vex 'vpblendvb', [1, 256, 0x66, 0x0F3A, 0], 0x4C, :mrmymm, :i4ymm
    addop_vex 'vpsllw', [1, 256, 0x66, 0x0F], 0xF1, :mrmymm
    addop_vex('vpsllw', [0, 256, 0x66, 0x0F], 0x71, 6, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex 'vpslld', [1, 256, 0x66, 0x0F], 0xF2, :mrmymm
    addop_vex('vpslld', [0, 256, 0x66, 0x0F], 0x72, 6, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex 'vpsllq', [1, 256, 0x66, 0x0F], 0xF3, :mrmymm
    addop_vex('vpsllq', [0, 256, 0x66, 0x0F], 0x73, 6, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex('vpslldq',[0, 256, 0x66, 0x0F], 0x73, 7, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex 'vpsraw', [1, 256, 0x66, 0x0F], 0xE1, :mrmymm
    addop_vex('vpsraw', [0, 256, 0x66, 0x0F], 0x71, 4, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex 'vpsrad', [1, 256, 0x66, 0x0F], 0xE2, :mrmymm
    addop_vex('vpsrad', [0, 256, 0x66, 0x0F], 0x72, 4, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex 'vpsrlw', [1, 256, 0x66, 0x0F], 0xD1, :mrmymm
    addop_vex('vpsrlw', [0, 256, 0x66, 0x0F], 0x71, 2, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex 'vpsrld', [1, 256, 0x66, 0x0F], 0xD2, :mrmymm
    addop_vex('vpsrld', [0, 256, 0x66, 0x0F], 0x72, 2, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex 'vpsrlq', [1, 256, 0x66, 0x0F], 0xD3, :mrmymm
    addop_vex('vpsrlq', [0, 256, 0x66, 0x0F], 0x73, 2, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }
    addop_vex('vpsrldq',[0, 256, 0x66, 0x0F], 0x73, 3, :u8, :modrmR) { |o| o.args[o.args.index(:modrm)] = :modrmymm }

    addop_vex 'vbroadcastss', [nil, 128, 0x66, 0x0F38, 0], 0x18, :mrmxmm, :modrmR
    addop_vex 'vbroadcastss', [nil, 256, 0x66, 0x0F38, 0], 0x18, :mrmymm, :modrmR
    addop_vex 'vbroadcastsd', [nil, 256, 0x66, 0x0F38, 0], 0x19, :mrmymm, :modrmR
    addop_vex 'vbroadcasti128', [nil, 256, 0x66, 0x0F38, 0], 0x5A, :mrmymm, :modrmA
    addop_vex 'vpblendd', [1, 128, 0x66, 0x0F3A, 0], 0x02, :mrmxmm, :u8
    addop_vex 'vpblendd', [1, 256, 0x66, 0x0F3A, 0], 0x02, :mrmymm, :u8
    addop_vex 'vpbroadcastb', [nil, 128, 0x66, 0x0F38, 0], 0x78, :mrmxmm
    addop_vex 'vpbroadcastb', [nil, 256, 0x66, 0x0F38, 0], 0x78, :mrmymm
    addop_vex 'vpbroadcastw', [nil, 128, 0x66, 0x0F38, 0], 0x79, :mrmxmm
    addop_vex 'vpbroadcastw', [nil, 256, 0x66, 0x0F38, 0], 0x79, :mrmymm
    addop_vex 'vpbroadcastd', [nil, 128, 0x66, 0x0F38, 0], 0x58, :mrmxmm
    addop_vex 'vpbroadcastd', [nil, 256, 0x66, 0x0F38, 0], 0x58, :mrmymm
    addop_vex 'vpbroadcastq', [nil, 128, 0x66, 0x0F38, 0], 0x59, :mrmxmm
    addop_vex 'vpbroadcastq', [nil, 256, 0x66, 0x0F38, 0], 0x59, :mrmymm
    addop_vex 'vpermd',     [1,   256, 0x66, 0x0F38, 0], 0x36, :mrmymm
    addop_vex 'vpermpd',    [nil, 256, 0x66, 0x0F3A, 1], 0x01, :mrmymm, :u8
    addop_vex 'vpermps',    [1,   256, 0x66, 0x0F38, 0], 0x16, :mrmymm, :u8
    addop_vex 'vpermq',     [nil, 256, 0x66, 0x0F3A, 1], 0x00, :mrmymm, :u8
    addop_vex 'vperm2i128', [1,   256, 0x66, 0x0F3A, 0], 0x46, :mrmymm, :u8
    addop_vex 'vextracti128', [nil, 256, 0x66, 0x0F3A, 0], 0x39, :mrmymm, :u8
    addop_vex 'vinserti128',  [1,   256, 0x66, 0x0F3A, 0], 0x38, :mrmymm, :u8
    addop_vex 'vpmaskmovd', [1, 128, 0x66, 0x0F38, 0], 0x8C, :mrmxmm, :modrmA
    addop_vex 'vpmaskmovd', [1, 256, 0x66, 0x0F38, 0], 0x8C, :mrmymm, :modrmA
    addop_vex 'vpmaskmovq', [1, 128, 0x66, 0x0F38, 1], 0x8C, :mrmxmm, :modrmA
    addop_vex 'vpmaskmovq', [1, 256, 0x66, 0x0F38, 1], 0x8C, :mrmymm, :modrmA
    addop_vex('vpmaskmovd', [1, 128, 0x66, 0x0F38, 0], 0x8E, :mrmxmm, :modrmA) { |o| o.args.reverse! }
    addop_vex('vpmaskmovd', [1, 256, 0x66, 0x0F38, 0], 0x8E, :mrmymm, :modrmA) { |o| o.args.reverse! }
    addop_vex('vpmaskmovq', [1, 128, 0x66, 0x0F38, 1], 0x8E, :mrmxmm, :modrmA) { |o| o.args.reverse! }
    addop_vex('vpmaskmovq', [1, 256, 0x66, 0x0F38, 1], 0x8E, :mrmymm, :modrmA) { |o| o.args.reverse! }
    addop_vex 'vpsllvd', [1, 128, 0x66, 0x0F38, 0], 0x47, :mrmxmm
    addop_vex 'vpsllvq', [1, 128, 0x66, 0x0F38, 1], 0x47, :mrmxmm
    addop_vex 'vpsllvd', [1, 256, 0x66, 0x0F38, 0], 0x47, :mrmymm
    addop_vex 'vpsllvq', [1, 256, 0x66, 0x0F38, 1], 0x47, :mrmymm
    addop_vex 'vpsravd', [1, 128, 0x66, 0x0F38, 0], 0x46, :mrmxmm
    addop_vex 'vpsravd', [1, 256, 0x66, 0x0F38, 0], 0x46, :mrmymm
    addop_vex 'vpsrlvd', [1, 128, 0x66, 0x0F38, 0], 0x45, :mrmxmm
    addop_vex 'vpsrlvq', [1, 128, 0x66, 0x0F38, 1], 0x45, :mrmxmm
    addop_vex 'vpsrlvd', [1, 256, 0x66, 0x0F38, 0], 0x45, :mrmymm
    addop_vex 'vpsrlvq', [1, 256, 0x66, 0x0F38, 1], 0x45, :mrmymm

    addop_vex('vpgatherdd', [2, 128, 0x66, 0x0F38, 0], 0x90, :mrmxmm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 128 }
    addop_vex('vpgatherdd', [2, 256, 0x66, 0x0F38, 0], 0x90, :mrmymm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 256 }
    addop_vex('vpgatherdq', [2, 128, 0x66, 0x0F38, 1], 0x90, :mrmxmm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 128 }
    addop_vex('vpgatherdq', [2, 256, 0x66, 0x0F38, 1], 0x90, :mrmymm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 256 }
    addop_vex('vpgatherqd', [2, 128, 0x66, 0x0F38, 0], 0x91, :mrmxmm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 128 }
    addop_vex('vpgatherqd', [2, 256, 0x66, 0x0F38, 0], 0x91, :mrmymm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 256 }
    addop_vex('vpgatherqq', [2, 128, 0x66, 0x0F38, 1], 0x91, :mrmxmm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 128 }
    addop_vex('vpgatherqq', [2, 256, 0x66, 0x0F38, 1], 0x91, :mrmymm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 256 }
    addop_vex('vgatherdps', [2, 128, 0x66, 0x0F38, 0], 0x92, :mrmxmm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 128 }
    addop_vex('vgatherdps', [2, 256, 0x66, 0x0F38, 0], 0x92, :mrmymm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 256 }
    addop_vex('vgatherdpd', [2, 128, 0x66, 0x0F38, 1], 0x92, :mrmxmm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 128 }
    addop_vex('vgatherdpd', [2, 256, 0x66, 0x0F38, 1], 0x92, :mrmymm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 256 }
    addop_vex('vgatherqps', [2, 128, 0x66, 0x0F38, 0], 0x93, :mrmxmm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 128 }
    addop_vex('vgatherqps', [2, 256, 0x66, 0x0F38, 0], 0x93, :mrmymm) { |o| o.props[:argsz] = 32 ; o.props[:mrmvex] = 256 }
    addop_vex('vgatherqpd', [2, 128, 0x66, 0x0F38, 1], 0x93, :mrmxmm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 128 }
    addop_vex('vgatherqpd', [2, 256, 0x66, 0x0F38, 1], 0x93, :mrmymm) { |o| o.props[:argsz] = 64 ; o.props[:mrmvex] = 256 }
  end

  def init_fma_only
    init_cpu_constants

    [['vfmaddsub', 'p', 0x86],
     ['vfmsubadd', 'p', 0x87],
     ['vfmadd',    'p', 0x88],
     ['vfmadd',    's', 0x89],
     ['vfmsub',    'p', 0x8A],
     ['vfmsub',    's', 0x8B],
     ['vfnmadd',   'p', 0x8C],
     ['vfnmadd',   's', 0x8D],
     ['vfnmsub',   'p', 0x8E],
     ['vfnmsub',   's', 0x8F]].each { |n1, n2, bin|
      addop_vex n1 + '132' + n2 + 's', [1, 128, 0x66, 0x0F38, 0], bin | 0x10, :mrmxmm
      addop_vex n1 + '132' + n2 + 's', [1, 256, 0x66, 0x0F38, 0], bin | 0x10, :mrmymm
      addop_vex n1 + '132' + n2 + 'd', [1, 128, 0x66, 0x0F38, 1], bin | 0x10, :mrmxmm
      addop_vex n1 + '132' + n2 + 'd', [1, 256, 0x66, 0x0F38, 1], bin | 0x10, :mrmymm
      addop_vex n1 + '213' + n2 + 's', [1, 128, 0x66, 0x0F38, 0], bin | 0x20, :mrmxmm
      addop_vex n1 + '213' + n2 + 's', [1, 256, 0x66, 0x0F38, 0], bin | 0x20, :mrmymm
      addop_vex n1 + '213' + n2 + 'd', [1, 128, 0x66, 0x0F38, 1], bin | 0x20, :mrmxmm
      addop_vex n1 + '213' + n2 + 'd', [1, 256, 0x66, 0x0F38, 1], bin | 0x20, :mrmymm
      addop_vex n1 + '231' + n2 + 's', [1, 128, 0x66, 0x0F38, 0], bin | 0x30, :mrmxmm
      addop_vex n1 + '231' + n2 + 's', [1, 256, 0x66, 0x0F38, 0], bin | 0x30, :mrmymm
      addop_vex n1 + '231' + n2 + 'd', [1, 128, 0x66, 0x0F38, 1], bin | 0x30, :mrmxmm
      addop_vex n1 + '231' + n2 + 'd', [1, 256, 0x66, 0x0F38, 1], bin | 0x30, :mrmymm

      # pseudo-opcodes aliases (swap arg0/arg1)
      addop_vex(n1 + '312' + n2 + 's', [1, 128, 0x66, 0x0F38, 0], bin | 0x10, :mrmxmm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '312' + n2 + 's', [1, 256, 0x66, 0x0F38, 0], bin | 0x10, :mrmymm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '312' + n2 + 'd', [1, 128, 0x66, 0x0F38, 1], bin | 0x10, :mrmxmm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '312' + n2 + 'd', [1, 256, 0x66, 0x0F38, 1], bin | 0x10, :mrmymm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '123' + n2 + 's', [1, 128, 0x66, 0x0F38, 0], bin | 0x20, :mrmxmm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '123' + n2 + 's', [1, 256, 0x66, 0x0F38, 0], bin | 0x20, :mrmymm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '123' + n2 + 'd', [1, 128, 0x66, 0x0F38, 1], bin | 0x20, :mrmxmm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '123' + n2 + 'd', [1, 256, 0x66, 0x0F38, 1], bin | 0x20, :mrmymm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '321' + n2 + 's', [1, 128, 0x66, 0x0F38, 0], bin | 0x30, :mrmxmm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '321' + n2 + 's', [1, 256, 0x66, 0x0F38, 0], bin | 0x30, :mrmymm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '321' + n2 + 'd', [1, 128, 0x66, 0x0F38, 1], bin | 0x30, :mrmxmm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
      addop_vex(n1 + '321' + n2 + 'd', [1, 256, 0x66, 0x0F38, 1], bin | 0x30, :mrmymm) { |o| o.args[0, 2] = o.args[0, 2].reverse }
    }
  end

  #
  # CPU family dependencies
  #

  def init_386_common
    init_386_common_only
  end

  def init_386
    init_386_common
    init_386_only
  end

  def init_387
    init_387_only
  end

  def init_486
    init_386
    init_387
    init_486_only
  end

  def init_pentium
    init_486
    init_pentium_only
  end

  def init_3dnow
    init_pentium
    init_3dnow_only
  end

  def init_p6
    init_pentium
    init_p6_only
  end

  def init_sse
    init_p6
    init_sse_only
  end

  def init_sse2
    init_sse
    init_sse2_only
  end

  def init_sse3
    init_sse2
    init_sse3_only
  end

  def init_ssse3
    init_sse3
    init_ssse3_only
  end

  def init_sse41
    init_ssse3
    init_sse41_only
  end

  def init_sse42
    init_sse41
    init_sse42_only
  end

  def init_avx
    init_sse42
    init_avx_only
  end

  def init_avx2
    init_avx
    init_fma_only
    init_avx2_only
  end

  def init_all
    init_avx2
    init_3dnow_only
    init_vmx_only
    init_aesni_only
  end

  alias init_latest init_all


  #
  # addop_* macros
  #

  def addop_macro1(name, num, *props)
    addop name, [(num << 3) | 4], nil, {:w => [0, 0]}, :reg_eax, :i, *props
    addop(name, [num << 3], :mrmw, {:d => [0, 1]}) { |o| o.args.reverse! }
    addop name, [0x80], num, {:w => [0, 0], :s => [0, 1]}, :i, *props
  end
  def addop_macro2(name, num)
    addop name, [0x0F, 0xBA], (4 | num), :u8
    addop(name, [0x0F, 0xA3 | (num << 3)], :mrm) { |op| op.args.reverse! }
  end
  def addop_macro3(name, num)
    addop name, [0xD0], num, {:w => [0, 0]}, :imm_val1
    addop name, [0xD2], num, {:w => [0, 0]}, :reg_cl
    addop name, [0xC0], num, {:w => [0, 0]}, :u8
  end

  def addop_macrotttn(name, bin, hint, *props, &blk)
    [%w{o},     %w{no},    %w{b nae c}, %w{nb ae nc},
     %w{z e},   %w{nz ne}, %w{be na}, %w{nbe a},
     %w{s},     %w{ns},    %w{p pe},  %w{np po},
     %w{l nge}, %w{nl ge}, %w{le ng}, %w{nle g}].each_with_index { |e, i|
      b = bin.dup
      if b[0] == 0x0F
        b[1] |= i
      else
        b[0] |= i
      end

      e.each { |k| addop(name + k, b.dup, hint, *props, &blk) }
    }
  end

  def addop_macrostr(name, bin, type)
    # addop(name, bin.dup, {:w => [0, 0]}) { |o| o.props[type] = true }     # TODO allow segment override
    addop(name+'b', bin) { |o| o.props[:opsz] = 16 ; o.props[type] = true }
    addop(name+'b', bin) { |o| o.props[:opsz] = 32 ; o.props[type] = true }
    bin = bin.dup
    bin[0] |= 1
    addop(name+'w', bin) { |o| o.props[:opsz] = 16 ; o.props[type] = true }
    addop(name+'d', bin) { |o| o.props[:opsz] = 32 ; o.props[type] = true }
  end

  def addop_macrofpu1(name, n)
    addop(name, [0xD8, n<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 32 }
    addop(name, [0xDC, n<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 64 }
    addop(name, [0xD8, 0xC0|(n<<3)], :regfp, {:d => [0, 2]}) { |o| o.args.reverse! }
  end
  def addop_macrofpu2(name, n, n2=0)
    addop(name, [0xDE|n2, n<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 16 }
    addop(name, [0xDA|n2, n<<3], :modrmA, :regfp0) { |o| o.props[:argsz] = 32 }
  end
  def addop_macrofpu3(name, n)
    addop_macrofpu2 name, n, 1
    addop(name, [0xDF, 0x28|(n<<3)], :modrmA, :regfp0) { |o| o.props[:argsz] = 64 }
  end

  def addop_macrogg(ggrng, name, bin, *args, &blk)
    ggoff = 1
    ggoff = 2 if bin[1] == 0x38 or bin[1] == 0x3A
    ggrng.each { |gg|
      bindup = bin.dup
      bindup[ggoff] |= gg
      sfx = %w(b w d q)[gg]
      addop name+sfx, bindup, *args, &blk
    }
  end

  def addop_macrossps(name, bin, hint, *a)
    addop name, bin.dup, hint, *a
    addop(name.sub(/ps$/, 'ss'), bin.dup, hint, *a) { |o| o.props[:needpfx] = 0xF3 }
  end

  def addop_macrosdpd(name, bin, hint, *a)
    addop(name, bin.dup, hint, *a) { |o| o.props[:needpfx] = 0x66 }
    addop(name.sub(/pd$/, 'sd'), bin.dup, hint, *a) { |o| o.props[:needpfx] = 0xF2 }
  end

  # special ret (iret/retf), that still default to 32b mode in x64
  def addop_macroret(name, bin, *args)
    addop(name + '.i32', bin.dup, nil, :stopexec, :setip, *args) { |o| o.props[:opsz] = 32 }
    addop(name + '.i16', bin.dup, nil, :stopexec, :setip, *args) { |o| o.props[:opsz] = 16 } if name != 'sysret'
    addop(name, bin.dup, nil, :stopexec, :setip, *args) { |o| o.props[:opsz] = @size }
  end

  # add an AVX instruction needing a VEX prefix (c4h/c5h)
  # the prefix is hardcoded
  def addop_vex(name, vexspec, bin, *args)
    argnr = vexspec.shift
    argt = vexspec.shift if argnr and vexspec.first.kind_of?(::Symbol)
    l = vexspec.shift
    pfx = vexspec.shift
    of = vexspec.shift
    w = vexspec.shift
    argt ||= (l == 128 ? :vexvxmm : :vexvymm)

    lpp = ((l >> 8) << 2) | [nil, 0x66, 0xF3, 0xF2].index(pfx)
    mmmmm = [nil, 0x0F, 0x0F38, 0x0F3A].index(of)

    c4bin = [0xC4, mmmmm, lpp, bin]
    c4bin[1] |= 1 << 7 if @size != 64
    c4bin[1] |= 1 << 6 if @size != 64
    c4bin[2] |= 1 << 7 if w == 1
    c4bin[2] |= 0xF << 3 if not argnr

    addop(name, c4bin, *args) { |o|
      o.args.insert(argnr, argt) if argnr

      o.fields[:vex_r] = [1, 7] if @size == 64
      o.fields[:vex_x] = [1, 6] if @size == 64
      o.fields[:vex_b] = [1, 5]
      o.fields[:vex_w] = [2, 7] if not w
      o.fields[:vex_vvvv] = [2, 3] if argnr

      yield o if block_given?
    }

    return if w == 1 or mmmmm != 1

    c5bin = [0xC5, lpp, bin]
    c5bin[1] |= 1 << 7 if @size != 64
    c5bin[1] |= 0xF << 3 if not argnr

    addop(name, c5bin, *args) { |o|
      o.args.insert(argnr, argt) if argnr

      o.fields[:vex_r] = [1, 7] if @size == 64
      o.fields[:vex_vvvv] = [1, 3] if argnr

      yield o if block_given?
    }
  end

  # helper function: creates a new Opcode based on the arguments, eventually
  # yields it for further customisation, and append it to the instruction set
  # is responsible of the creation of disambiguating opcodes if necessary (:s flag hardcoding)
  def addop(name, bin, hint=nil, *argprops)
    fields = (argprops.first.kind_of?(Hash) ? argprops.shift : {})
    op = Opcode.new name, bin
    op.fields.replace fields

    case hint
    when nil

    when :mrm, :mrmw, :mrmA
      op.fields[:reg]   = [bin.length, 3]
      op.fields[:modrm] = [bin.length, 0]
      op.fields[:w]     = [bin.length - 1, 0] if hint == :mrmw
      argprops.unshift :reg, :modrm
      argprops << :modrmA if hint == :mrmA
      op.bin << 0
    when :reg
      op.fields[:reg] = [bin.length-1, 0]
      argprops.unshift :reg
    when :regfp
      op.fields[:regfp] = [bin.length-1, 0]
      argprops.unshift :regfp, :regfp0
    when :modrmA
      op.fields[:modrm] = [bin.length-1, 0]
      argprops << :modrm << :modrmA

    when Integer		# mod/m, reg == opcode extension = hint
      op.fields[:modrm] = [bin.length, 0]
      op.bin << (hint << 3)
      argprops.unshift :modrm

    when :mrmmmx
      op.fields[:regmmx] = [bin.length, 3]
      op.fields[:modrm] = [bin.length, 0]
      bin << 0
      argprops.unshift :regmmx, :modrmmmx
    when :mrmxmm
      op.fields[:regxmm] = [bin.length, 3]
      op.fields[:modrm] = [bin.length, 0]
      bin << 0
      argprops.unshift :regxmm, :modrmxmm
    when :mrmymm
      op.fields[:regymm] = [bin.length, 3]
      op.fields[:modrm] = [bin.length, 0]
      bin << 0
      argprops.unshift :regymm, :modrmymm
    else
      raise SyntaxError, "invalid hint #{hint.inspect} for #{name}"
    end

    argprops.each { |a|
      op.props[a] = true if @valid_props[a]
      op.args << a if @valid_args[a]
    }

    yield op if block_given?

    if $DEBUG
      argprops -= @valid_props.keys + @valid_args.keys
      raise "Invalid opcode definition: #{name}: unknown #{argprops.inspect}" unless argprops.empty?

      argprops = (op.props.keys - @valid_props.keys) + (op.args - @valid_args.keys) + (op.fields.keys - @fields_mask.keys)
      raise "Invalid opcode customisation: #{name}: #{argprops.inspect}" unless argprops.empty?
    end

    addop_post(op)
  end

  # this recursive method is in charge of Opcode duplication (eg to hardcode some flag)
  def addop_post(op)
    if df = op.fields.delete(:d)
      # hardcode the bit
      dop = op.dup
      addop_post dop

      op.bin[df[0]] |= 1 << df[1]
      op.args.reverse!
      addop_post op

      return
    elsif wf = op.fields.delete(:w)
      # hardcode the bit
      dop = op.dup
      dop.props[:argsz] = 8
      # 64-bit w=0 s=1 => UD
      dop.fields.delete(:s) if @size == 64
      addop_post dop

      op.bin[wf[0]] |= 1 << wf[1]
      addop_post op

      return
    elsif sf = op.fields.delete(:s)
      # add explicit choice versions, with lower precedence (so that disassembling will return the general version)
      # eg "jmp", "jmp.i8", "jmp.i"
      # also hardcode the bit
      op32 = op
      addop_post op32

      op8 = op.dup
      op8.bin[sf[0]] |= 1 << sf[1]
      op8.args.map! { |arg| arg == :i ? :i8 : arg }
      addop_post op8

      op32 = op32.dup
      op32.name << '.i'
      addop_post op32

      op8 = op8.dup
      op8.name << '.i8'
      addop_post op8

      return
    elsif op.args.first == :regfp0
      dop = op.dup
      dop.args.delete :regfp0
      addop_post dop
    end

    if op.props[:needpfx]
      @opcode_list.unshift op
    else
      @opcode_list << op
    end

    if (op.args == [:i] or op.args == [:farptr] or op.name == 'ret') and op.name !~ /\.i/
      # define opsz-override version for ambiguous opcodes
      op16 = op.dup
      op16.name << '.i16'
      op16.props[:opsz] = 16
      @opcode_list << op16
      op32 = op.dup
      op32.name << '.i32'
      op32.props[:opsz] = 32
      @opcode_list << op32
    elsif op.props[:strop] or op.props[:stropz] or op.args.include? :mrm_imm or
        op.args.include? :modrm or op.name =~ /loop|xlat/
      # define adsz-override version for ambiguous opcodes (TODO allow movsd edi / movsd di syntax)
      # XXX loop pfx 67 = eip+cx, 66 = ip+ecx
      op16 = op.dup
      op16.name << '.a16'
      op16.props[:adsz] = 16
      @opcode_list << op16
      op32 = op.dup
      op32.name << '.a32'
      op32.props[:adsz] = 32
      @opcode_list << op32
    end
  end
end
end
