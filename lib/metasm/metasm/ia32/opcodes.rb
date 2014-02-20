#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/main'

module Metasm
class Ia32
  def init_cpu_constants
    @opcode_list ||= []
    @fields_mask.update :w => 1, :s => 1, :d => 1, :modrm => 0xc7,
      :reg => 7, :eeec => 7, :eeed => 7, :seg2 => 3, :seg3 => 7,
      :regfp => 7, :regmmx => 7, :regxmm => 7
    @fields_mask[:seg2A]    = @fields_mask[:seg2]
    @fields_mask[:seg3A]    = @fields_mask[:seg3]
    @fields_mask[:modrmA]   = @fields_mask[:modrm]

    @valid_args.concat [:i, :i8, :u8, :u16, :reg, :seg2, :seg2A,
      :seg3, :seg3A, :eeec, :eeed, :modrm, :modrmA, :mrm_imm,
      :farptr, :imm_val1, :imm_val3, :reg_cl, :reg_eax,
      :reg_dx, :regfp, :regfp0, :modrmmmx, :regmmx,
      :modrmxmm, :regxmm] - @valid_args

    @valid_props.concat [:strop, :stropz, :opsz, :argsz, :setip,
      :stopexec, :saveip, :unsigned_imm, :random, :needpfx,
      :xmmx] - @valid_props
  end

  # only most common instructions from the 386 instruction set
  # inexhaustive list :
  # no aaa, arpl, mov crX, call/jmp/ret far, in/out, bts, xchg...
  def init_386_common_only
    init_cpu_constants

    addop_macro1 'adc', 2
    addop_macro1 'add', 0
    addop_macro1 'and', 4, :u
    addop 'bswap', [0x0F, 0xC8], :reg
    addop 'call',  [0xE8], nil,  {}, :stopexec, :setip, :i, :saveip
    addop 'call',  [0xFF], 2,    {}, :stopexec, :setip, :saveip
    addop('cbw',   [0x98]) { |o| o.props[:opsz] = 16 }
    addop('cwde',  [0x98]) { |o| o.props[:opsz] = 32 }
    addop('cdqe',  [0x98]) { |o| o.props[:opsz] = 64 }
    addop('cwd',   [0x99]) { |o| o.props[:opsz] = 16 }
    addop('cdq',   [0x99]) { |o| o.props[:opsz] = 32 }
    addop('cqo',   [0x99]) { |o| o.props[:opsz] = 64 }
    addop_macro1 'cmp', 7
    addop_macrostr 'cmps',  [0xA6], :stropz
    addop 'dec',   [0x48], :reg
    addop 'dec',   [0xFE], 1,    {:w => [0, 0]}
    addop 'div',   [0xF6], 6,    {:w => [0, 0]}
    addop 'enter', [0xC8], nil,  {}, :u16, :u8
    addop 'idiv',  [0xF6], 7,    {:w => [0, 0]}
    addop 'imul',  [0xF6], 5,    {:w => [0, 0]}, :reg_eax
    addop 'imul',  [0x0F, 0xAF], :mrm
    addop 'imul',  [0x69], :mrm, {:s => [0, 1]}, :i
    addop 'inc',   [0x40], :reg
    addop 'inc',   [0xFE], 0,    {:w => [0, 0]}
    addop 'int',   [0xCC], nil,  {}, :imm_val3, :stopexec
    addop 'int',   [0xCD], nil,  {}, :u8
    addop_macrotttn 'j', [0x70], nil, {}, :setip, :i8
    addop_macrotttn 'j', [0x0F, 0x80], nil, {}, :setip, :i
    addop 'jmp',   [0xE9], nil,  {:s => [0, 1]}, :setip, :i,  :stopexec
    addop 'jmp',   [0xFF], 4,    {}, :setip, :stopexec
    addop 'lea',   [0x8D], :mrmA
    addop 'leave', [0xC9]
    addop_macrostr 'lods',  [0xAC], :strop
    addop 'loop',  [0xE2], nil,  {}, :setip, :i8
    addop 'loopz', [0xE1], nil,  {}, :setip, :i8
    addop 'loope', [0xE1], nil,  {}, :setip, :i8
    addop 'loopnz',[0xE0], nil,  {}, :setip, :i8
    addop 'loopne',[0xE0], nil,  {}, :setip, :i8
    addop 'mov',   [0xA0], nil,  {:w => [0, 0], :d => [0, 1]}, :mrm_imm, :reg_eax
    addop 'mov',   [0x88], :mrmw,{:d => [0, 1]}
    addop 'mov',   [0xB0], :reg, {:w => [0, 3]}, :u
    addop 'mov',   [0xC6], 0,    {:w => [0, 0]}, :u
    addop_macrostr 'movs',  [0xA4], :strop
    addop 'movsx', [0x0F, 0xBE], :mrmw
    addop 'movzx', [0x0F, 0xB6], :mrmw
    addop 'mul',   [0xF6], 4,    {:w => [0, 0]}
    addop 'neg',   [0xF6], 3,    {:w => [0, 0]}
    addop 'nop',   [0x90]
    addop 'not',   [0xF6], 2,    {:w => [0, 0]}
    addop_macro1 'or', 1, :u
    addop 'pop',   [0x58], :reg
    addop 'pop',   [0x8F], 0
    addop 'push',  [0x50], :reg
    addop 'push',  [0xFF], 6
    addop 'push',  [0x68], nil,  {:s => [0, 1]}, :u
    addop 'ret',   [0xC3], nil,  {}, :stopexec, :setip
    addop 'ret',   [0xC2], nil,  {}, :stopexec, :u16, :setip
    addop_macro3 'rol', 0
    addop_macro3 'ror', 1
    addop_macro3 'sar', 7
    addop_macro1 'sbb', 3
    addop_macrostr 'scas',  [0xAE], :stropz
    addop_macrotttn('set', [0x0F, 0x90], 0) { |o| o.props[:argsz] = 8 }
    addop_macrotttn('set', [0x0F, 0x90], :mrm) { |o| o.props[:argsz] = 8 ; o.args.reverse! }	# :reg field is unused
    addop_macro3 'shl', 4
    addop_macro3 'sal', 6
    addop 'shld',  [0x0F, 0xA4], :mrm, {}, :u8
    addop 'shld',  [0x0F, 0xA5], :mrm, {}, :reg_cl
    addop_macro3 'shr', 5
    addop 'shrd',  [0x0F, 0xAC], :mrm, {}, :u8
    addop 'shrd',  [0x0F, 0xAD], :mrm, {}, :reg_cl
    addop_macrostr 'stos',  [0xAA], :strop
    addop_macro1 'sub', 5
    addop 'test',  [0x84], :mrmw
    addop 'test',  [0xA8], nil,  {:w => [0, 0]}, :reg_eax, :u
    addop 'test',  [0xF6], 0,    {:w => [0, 0]}, :u
    addop 'xchg',  [0x90], :reg, {}, :reg_eax
    addop('xchg',  [0x90], :reg, {}, :reg_eax) { |o| o.args.reverse! }	# xchg eax, ebx == xchg ebx, eax)
    addop 'xchg',  [0x86], :mrmw
    addop('xchg',  [0x86], :mrmw) { |o| o.args.reverse! }
    addop_macro1 'xor', 6, :u
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
    addop 'call',  [0x9A], nil,  {}, :stopexec, :setip, :farptr, :saveip
    addop 'callf', [0x9A], nil,  {}, :stopexec, :setip, :farptr, :saveip
    addop 'callf', [0xFF], 3,    {}, :stopexec, :setip, :saveip
    addop 'clc',   [0xF8]
    addop 'cld',   [0xFC]
    addop 'cli',   [0xFA]
    addop 'clts',  [0x0F, 0x06]
    addop 'cmc',   [0xF5]
    addop('cmpxchg',[0x0F, 0xB0], :mrmw) { |o| o.args.reverse! }
    addop 'cpuid', [0x0F, 0xA2]
    addop 'daa',   [0x27]
    addop 'das',   [0x2F]
    addop 'hlt',   [0xF4], nil, {}, :stopexec
    addop 'in',    [0xE4], nil,  {:w => [0, 0]}, :reg_eax, :u8
    addop 'in',    [0xE4], nil,  {:w => [0, 0]}, :u8
    addop 'in',    [0xEC], nil,  {:w => [0, 0]}, :reg_eax, :reg_dx
    addop 'in',    [0xEC], nil,  {:w => [0, 0]}, :reg_eax
    addop 'in',    [0xEC], nil,  {:w => [0, 0]}
    addop_macrostr 'ins',   [0x6C], :strop
    addop 'into',  [0xCE]
    addop 'invd',  [0x0F, 0x08]
    addop 'invlpg',[0x0F, 0x01, 7<<3], :modrmA
    addop 'iret',  [0xCF], nil,  {}, :stopexec, :setip
    addop 'iretd', [0xCF], nil,  {}, :stopexec, :setip
    addop('jcxz',  [0xE3], nil,  {}, :setip, :i8) { |o| o.props[:opsz] = 16 }
    addop('jecxz', [0xE3], nil,  {}, :setip, :i8) { |o| o.props[:opsz] = 32 }
    addop 'jmp',   [0xEA], nil,  {}, :farptr, :setip, :stopexec
    addop 'jmpf',  [0xEA], nil,  {}, :farptr, :setip, :stopexec
    addop 'jmpf',  [0xFF], 5,    {}, :stopexec, :setip		# reg ?
    addop 'lahf',  [0x9F]
    addop 'lar',   [0x0F, 0x02], :mrm
    addop 'lds',   [0xC5], :mrmA
    addop 'les',   [0xC4], :mrmA
    addop 'lfs',   [0x0F, 0xB4], :mrmA
    addop 'lgs',   [0x0F, 0xB5], :mrmA
    addop 'lgdt',  [0x0F, 0x01], 2
    addop 'lidt',  [0x0F, 0x01, 3<<3], :modrmA
    addop 'lldt',  [0x0F, 0x00], 2
    addop 'lmsw',  [0x0F, 0x01], 6
# prefix	addop 'lock',  [0xF0]
    addop 'lsl',   [0x0F, 0x03], :mrm
    addop 'lss',   [0x0F, 0xB2], :mrmA
    addop 'ltr',   [0x0F, 0x00], 3
    addop('mov',   [0x0F, 0x20, 0xC0], :reg, {:d => [1, 1], :eeec => [2, 3]}, :eeec) { |op| op.args.reverse! }
    addop('mov',   [0x0F, 0x21, 0xC0], :reg, {:d => [1, 1], :eeed => [2, 3]}, :eeed) { |op| op.args.reverse! }
    addop('mov',   [0x8C], 0,    {:d => [0, 1], :seg3 => [1, 3]}, :seg3) { |op| op.args.reverse! }
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
    addop 'rdtsc', [0x0F, 0x31], nil, {}, :random
    addop 'retf',  [0xCB], nil,  {}, :stopexec, :setip
    addop 'retf',  [0xCA], nil,  {}, :stopexec, :u16, :setip
    addop 'rsm',   [0x0F, 0xAA], nil, {}, :stopexec
    addop 'sahf',  [0x9E]
    addop 'sgdt',  [0x0F, 0x01, 0<<3], :modrmA
    addop 'sidt',  [0x0F, 0x01, 1<<3], :modrmA
    addop 'sldt',  [0x0F, 0x00], 0
    addop 'smsw',  [0x0F, 0x01], 4
    addop 'stc',   [0xF9]
    addop 'std',   [0xFD]
    addop 'sti',   [0xFB]
    addop 'str',   [0x0F, 0x00], 1
    addop 'ud2',   [0x0F, 0x0B]
    addop 'verr',  [0x0F, 0x00], 4
    addop 'verw',  [0x0F, 0x00], 5
    addop 'wait',  [0x9B]
    addop 'wbinvd',[0x0F, 0x09]
    addop 'wrmsr', [0x0F, 0x30]
    addop('xadd',  [0x0F, 0xC0], :mrmw) { |o| o.args.reverse! }
    addop 'xlat',  [0xD7]

# pfx:  addrsz = 0x67, lock = 0xf0, opsz = 0x66, repnz = 0xf2, rep/repz = 0xf3
#	cs/nojmp = 0x2E, ds/jmp = 0x3E, es = 0x26, fs = 0x64, gs = 0x65, ss = 0x36
    # undocumented opcodes
    # TODO put these in the right place (486/P6/...)
    addop 'aam',   [0xD4], nil,  {}, :u8
    addop 'aad',   [0xD5], nil,  {}, :u8
    addop 'setalc', [0xD6]
    addop 'salc', [0xD6]
    addop 'icebp', [0xF1]
    #addop 'loadall',[0x0F, 0x07]	# conflict with syscall
    addop 'ud2',   [0x0F, 0xB9]
    addop 'umov',  [0x0F, 0x10], :mrmw,{:d => [1, 1]}
  end

  def init_387_only
    init_cpu_constants

    addop 'f2xm1', [0xD9, 0xF0]
    addop 'fabs',  [0xD9, 0xE1]
    addop_macrofpu1 'fadd',  0
    addop 'faddp', [0xDE, 0xC0], :regfp
    addop 'faddp', [0xDE, 0xC1]
    addop('fbld',  [0xDF, 4<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 80 }
    addop('fbstp', [0xDF, 6<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 80 }
    addop 'fchs',  [0xD9, 0xE0], nil,  {}, :regfp0
    addop 'fnclex',      [0xDB, 0xE2]
    addop_macrofpu1 'fcom',  2
    addop_macrofpu1 'fcomp', 3
    addop 'fcompp',[0xDE, 0xD9]
    addop 'fcomip',[0xDF, 0xF0], :regfp
    addop 'fcos',  [0xD9, 0xFF], nil,  {}, :regfp0
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
    addop('fld', [0xD9, 0<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 32 }
    addop('fld', [0xDD, 0<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 64 }
    addop('fld', [0xDB, 5<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 80 }
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
    addop('fst',  [0xD9, 2<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 32 }
    addop('fst',  [0xDD, 2<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 64 }
    addop 'fst',  [0xD9, 0xD0], :regfp
    addop('fstp', [0xD9, 3<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 32 }
    addop('fstp', [0xDD, 3<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 64 }
    addop('fstp', [0xDB, 7<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 80 }
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
    # TODO add new segments (fs/gs) ?
  end

  def init_pentium_only
    init_cpu_constants

    addop 'cmpxchg8b', [0x0F, 0xC7], 1
    # lock cmpxchg8b eax
    #addop 'f00fbug', [0xF0, 0x0F, 0xC7, 0xC8]

    # mmx
    addop 'emms',  [0x0F, 0x77]
    addop('movd',  [0x0F, 0x6E], :mrmmmx, {:d => [1, 4]}) { |o| o.args[o.args.index(:modrmmmx)] = :modrm ; o.args.reverse! }
    addop('movq',  [0x0F, 0x6F], :mrmmmx, {:d => [1, 4]}) { |o| o.args.reverse! }
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
    addop_macrommx 1..3, 'psll', 3
    addop_macrommx 1..2, 'psra', 2
    addop_macrommx 1..3, 'psrl', 1
    addop_macrogg 0..2, 'psub',  [0x0F, 0xF8], :mrmmmx
    addop_macrogg 0..1, 'psubs', [0x0F, 0xE8], :mrmmmx
    addop_macrogg 0..1, 'psubus',[0x0F, 0xD8], :mrmmmx
    addop_macrogg 1..3, 'punchkh', [0x0F, 0x68], :mrmmmx
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
    addop 'sysret',  [0x0F, 0x07]	# AMD
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
    addop '3dnow', [0x0F, 0x0F], :mrmmmx, {}, :u8

    addop 'femms', [0x0F, 0x0E]
    addop 'prefetch',  [0x0F, 0x0D, 0<<3], :modrmA
    addop 'prefetchw', [0x0F, 0x0D, 1<<3], :modrmA
  end

  def init_sse_only
    init_cpu_constants

    addop_macrossps 'addps', [0x0F, 0xA8], :mrmxmm
    addop 'andnps',  [0x0F, 0xAA], :mrmxmm
    addop 'andps',   [0x0F, 0xA4], :mrmxmm
    addop_macrossps 'cmpps', [0x0F, 0xC2], :mrmxmm
    addop 'comiss',  [0x0F, 0x2F], :mrmxmm

    [['pi2ps', 0x2A], ['ps2pi', 0x2D], ['tps2pi', 0x2C]].each { |str, bin|
      addop('cvt' << str, [0x0F, bin], :mrmxmm) { |o| o.args[o.args.index(:modrmxmm)] = :modrmmmx }
      addop('cvt' << str.tr('p', 's'), [0x0F, bin], :mrmxmm) { |o| o.args[o.args.index(:modrmxmm)] = :modrm ; o.props[:needpfx] = 0xF3 }
    }

    addop_macrossps 'divps', [0x0F, 0x5E], :mrmxmm
    addop 'ldmxcsr', [0x0F, 0xAE, 2<<3], :modrmA
    addop_macrossps 'maxps', [0x0F, 0x5F], :mrmxmm
    addop_macrossps 'minps', [0x0F, 0x5D], :mrmxmm
    addop('movaps',  [0x0F, 0x28], :mrmxmm, {:d => [1, 0]}) { |o| o.args.reverse! }
    addop('movd',    [0x0F, 0x6E], :mrmxmm, {:d => [1, 4]}) { |o| o.args[o.args.index(:modrmxmm)] = :modrm ; o.args.reverse! ; o.props[:needpfx] = 0x66 }
    addop('movdqa',  [0x0F, 0x6F], :mrmxmm, {:d => [1, 4]}) { |o| o.args.reverse! ; o.props[:needpfx] = 0x66 }

    # movhlps(reg, reg){nomem} == movlps(reg, mrm){no restriction}...
    addop 'movhlps', [0x0F, 0x12], :mrmxmm, {:d => [1, 0]}
    addop 'movlps',  [0x0F, 0x12], :mrmxmm, {:d => [1, 0]}
    addop 'movlhps', [0x0F, 0x16], :mrmxmm, {:d => [1, 0]}
    addop 'movhps',  [0x0F, 0x16], :mrmxmm, {:d => [1, 0]}

    addop 'movmskps',[0x0F, 0x50, 0xC0], nil, {:reg => [2, 3], :regxmm => [2, 0]}, :regxmm, :reg
    addop('movss',   [0x0F, 0x10], :mrmxmm, {:d => [1, 0]}) { |o| o.props[:needpfx] = 0xF3 }
    addop 'movups',  [0x0F, 0x10], :mrmxmm, {:d => [1, 0]}
    addop_macrossps 'mulps', [0x0F, 0x59], :mrmxmm
    addop 'orps',    [0x0F, 0x56], :mrmxmm
    addop_macrossps 'rcpps',  [0x0F, 0x53], :mrmxmm
    addop_macrossps 'rsqrtps',[0x0F, 0x52], :mrmxmm
    addop 'shufps',  [0x0F, 0xC6], :mrmxmm, {}, :u8
    addop_macrossps 'sqrtps', [0x0F, 0x51], :mrmxmm
    addop 'stmxcsr', [0x0F, 0xAE, 3<<3], :modrmA
    addop_macrossps 'subps', [0x0F, 0x5C], :mrmxmm
    addop 'ucomiss', [0x0F, 0x2E], :mrmxmm
    addop 'unpckhps',[0x0F, 0x15], :mrmxmm
    addop 'unpcklps',[0x0F, 0x14], :mrmxmm
    addop 'xorps',   [0x0F, 0x57], :mrmxmm

    # start of integer instruction (accept opsz override prefix to access xmm)
    addop('pavgb',   [0x0F, 0xE0], :mrmmmx) { |o| o.props[:xmmx] = true }
    addop('pavgw',   [0x0F, 0xE3], :mrmmmx) { |o| o.props[:xmmx] = true }
# TODO		addop('pextrw',  [0x0F, 0xC5], :mrmmmx) { |o| o.fields[:reg] = o.fields.delete(:regmmx) } { |o| o.props[:xmmx] = true ; o.args << :u8 }
#		addop('pinsrw',  [0x0F, 0xC4], :mrmmmx) { |o| o.fields[:reg] = o.fields.delete(:regmmx) } { |o| o.props[:xmmx] = true ; o.args << :u8 }
    addop('pmaxsw',  [0x0F, 0xEE], :mrmmmx) { |o| o.props[:xmmx] = true }
    addop('pmaxub',  [0x0F, 0xDE], :mrmmmx) { |o| o.props[:xmmx] = true }
    addop('pminsw',  [0x0F, 0xEA], :mrmmmx) { |o| o.props[:xmmx] = true }
    addop('pminub',  [0x0F, 0xDA], :mrmmmx) { |o| o.props[:xmmx] = true }
#		addop('pmovmskb',[0x0F, 0xD4], :mrmmmx) { |o| o.fields[:reg] = o.fields.delete(:regmmx) } ) { |o| o.props[:xmmx] = true } # no mem ref in the mrm
    addop('pmulhuw', [0x0F, 0xE4], :mrmmmx) { |o| o.props[:xmmx] = true }
    addop('psadbw',  [0x0F, 0xF6], :mrmmmx) { |o| o.props[:xmmx] = true }
    addop('pshufw',  [0x0F, 0x70], :mrmmmx) { |o| o.props[:xmmx] = true ; o.args << :u8 }
    addop('maskmovq',[0x0F, 0xF7], :mrmmmx) { |o| o.props[:xmmx] = true } # nomem
    addop('movntq',  [0x0F, 0xE7], :mrmmmx) { |o| o.props[:xmmx] = true }
    addop 'movntps', [0x0F, 0x2B], :mrmxmm
    addop 'prefetcht0', [0x0F, 0x18, 1<<3], :modrmA
    addop 'prefetcht1', [0x0F, 0x18, 2<<3], :modrmA
    addop 'prefetcht2', [0x0F, 0x18, 3<<3], :modrmA
    addop 'prefetchnta',[0x0F, 0x18, 0<<3], :modrmA
    addop 'sfence',  [0x0F, 0xAE, 0xF8]
  end

  # XXX must be done after init_sse (patches :regmmx opcodes)
  # TODO complete the list
  def init_sse2_only
    init_cpu_constants

    @opcode_list.each { |o| o.props[:xmmx] = true if o.args.include? :regmmx and o.args.include? :modrmmmx }

    # TODO <..blabla...integer...blabla..>

    # nomem
    addop('clflush', [0x0F, 0xAE, 7<<3], :modrmA) { |o| o.props[:argsz] = 8 }
    addop('maskmovdqu', [0x0F, 0xF7], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('movntpd', [0x0F, 0x2B], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('movntdq', [0x0F, 0xE7], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop 'movnti',  [0x0F, 0xC3], :mrm
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
    addop('lddqu',    [0x0F, 0xF0], :mrmxmm) { |o| o.args[o.args.index(:modrmxmm)] = :modrmA ; o.props[:needpfx] = 0xF2 }
    addop('movddup',  [0x0F, 0x12], :mrmxmm) { |o| o.props[:needpfx] = 0xF2 }
    addop('movshdup', [0x0F, 0x16], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }
    addop('movsldup', [0x0F, 0x12], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }
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

    addop('movbe',    [0x0F, 0x38, 0xF0], :mrm, { :d => [2, 0] }) { |o| o.args.reverse! }
    addop 'xgetbv', [0x0F, 0x01, 0xD0]
    addop 'xsetbv', [0x0F, 0x01, 0xD1]
    addop 'rdtscp', [0x0F, 0x01, 0xF9]
    addop 'xrstor', [0x0F, 0xAE, 5<<3], :modrmA
    addop 'xsave',  [0x0F, 0xAE, 4<<3], :modrmA
    addop 'nop', [0x0F, 0x1F], 0	# which family does this belong to ?
  end

  def init_sse42_only
    init_cpu_constants

    addop('crc32', [0x0F, 0x38, 0xF0], :mrmw) { |o| o.props[:needpfx] = 0xF2 }
    addop('pcmpestrm', [0x0F, 0x3A, 0x60], :mrmxmm, {}, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpestri', [0x0F, 0x3A, 0x61], :mrmxmm, {}, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpistrm', [0x0F, 0x3A, 0x62], :mrmxmm, {}, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpistri', [0x0F, 0x3A, 0x63], :mrmxmm, {}, :i8) { |o| o.props[:needpfx] = 0x66 }
    addop('pcmpgtq', [0x0F, 0x38, 0x37], :mrmxmm) { |o| o.props[:needpfx] = 0x66 }
    addop('popcnt',  [0x0F, 0xB8], :mrmxmm) { |o| o.props[:needpfx] = 0xF3 }
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

  def init_vmx
    init_sse3
    init_vmx_only
  end
  
  def init_all
    init_vmx
    init_sse42_only
    init_3dnow_only
  end

  alias init_latest init_all


  #
  # addop_* macros
  #

  def addop_macro1(name, num, immtype=:i)
    addop name, [(num << 3) | 4], nil, {:w => [0, 0]}, :reg_eax, immtype
    addop name, [num << 3], :mrmw, {:d => [0, 1]}
    addop name, [0x80], num, {:w => [0, 0], :s => [0, 1]}, immtype
  end
  def addop_macro2(name, num)
    addop name, [0x0F, 0xBA], (4 | num), {}, :u8
    addop(name, [0x0F, 0xA3 | (num << 3)], :mrm) { |op| op.args.reverse! }
  end
  def addop_macro3(name, num)
    addop name, [0xD0], num, {:w => [0, 0]}, :imm_val1
    addop name, [0xD2], num, {:w => [0, 0]}, :reg_cl
    addop name, [0xC0], num, {:w => [0, 0]}, :u8
  end

  def addop_macrotttn(name, bin, hint, fields = {}, *props, &blk)
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

      e.each { |k| addop(name + k, b.dup, hint, fields.dup, *props, &blk) }
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
    addop(name, [0xD8, n<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 32 }
    addop(name, [0xDC, n<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 64 }
    addop name, [0xD8, 0xC0|(n<<3)], :regfp, {:d => [0, 2]}
  end
  def addop_macrofpu2(name, n, n2=0)
    addop(name, [0xDE|n2, n<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 16 }
    addop(name, [0xDA|n2, n<<3], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 32 }
  end
  def addop_macrofpu3(name, n)
    addop_macrofpu2 name, n, 1
    addop(name, [0xDF, 0x28|(n<<3)], :modrmA, {}, :regfp0) { |o| o.props[:argsz] = 64 }
  end

  def addop_macrogg(ggrng, name, bin, *args, &blk)
    ggrng.each { |gg|
      bindup = bin.dup
      bindup[1] |= gg
      sfx = %w(b w d q)[gg]
      addop name+sfx, bindup, *args, &blk
    }
  end

  def addop_macrommx(ggrng, name, val)
    addop_macrogg ggrng, name, [0x0F, 0xC0 | (val << 4)], :mrmmmx
    addop_macrogg ggrng, name, [0x0F, 0x70, 0xC0 | (val << 4)], nil, {:regmmx => [2, 0]}, :u8
  end

  def addop_macrossps(name, bin, hint)
    # don't allow fields argument, as this will be modified by addop (.dup it if needed)
    addop name, bin, hint
    addop(name.tr('p', 's'), bin, hint) { |o| o.props[:needpfx] = 0xF3 }
  end

  # helper function: creates a new Opcode based on the arguments, eventually
  # yields it for further customisation, and append it to the instruction set
  # is responsible of the creation of disambiguating opcodes if necessary (:s flag hardcoding)
  def addop(name, bin, hint=nil, fields={}, *argprops)
    op = Opcode.new name, bin
    op.fields.replace fields

    case hint
    when nil

    when :mrm, :mrmw, :mrmA
      h = (hint == :mrmA ? :modrmA : :modrm)
      op.fields[:reg]   = [bin.length, 3]
      op.fields[h] = [bin.length, 0]
      op.fields[:w]     = [bin.length - 1, 0] if hint == :mrmw
      argprops.unshift :reg, h
      op.bin << 0
    when :reg
      op.fields[:reg] = [bin.length-1, 0]
      argprops.unshift :reg
    when :regfp
      op.fields[:regfp] = [bin.length-1, 0]
      argprops.unshift :regfp, :regfp0
    when :modrmA
      op.fields[:modrmA] = [bin.length-1, 0]
      argprops << :modrmA

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
    else
      raise SyntaxError, "invalid hint #{hint.inspect} for #{name}"
    end

    if argprops.index(:u)
      argprops << :unsigned_imm
      argprops[argprops.index(:u)] = :i
    end

    (argprops & @valid_props).each { |p| op.props[p] = true }
    argprops -= @valid_props

    op.args.concat(argprops & @valid_args)
    argprops -= @valid_args

    raise "Invalid opcode definition: #{name}: unknown #{argprops.inspect}" unless argprops.empty?

    yield op if block_given?

    argprops = (op.props.keys - @valid_props) + (op.args - @valid_args) + (op.fields.keys - @fields_mask.keys)
    raise "Invalid opcode customisation: #{name}: #{argprops.inspect}" unless argprops.empty?

    addop_post(op)
  end

  # this recursive method is in charge of Opcode duplication (eg to hardcode some flag)
  def addop_post(op)
    dupe = lambda { |o|
      dop = Opcode.new o.name.dup
      dop.bin, dop.fields, dop.props, dop.args = o.bin.dup, o.fields.dup, o.props.dup, o.args.dup
      dop
    }
    if df = op.fields.delete(:d)
      # hardcode the bit
      dop = dupe[op]
      dop.args.reverse!
      addop_post dop

      op.bin[df[0]] |= 1 << df[1]
      addop_post op

      return
    elsif wf = op.fields.delete(:w)
      # hardcode the bit
      dop = dupe[op]
      dop.props[:argsz] = 8
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

      op8 = dupe[op]
      op8.bin[sf[0]] |= 1 << sf[1]
      op8.args.map! { |arg| arg == :i ? :i8 : arg }
      addop_post op8

      op32 = dupe[op32]
      op32.name << '.i'
      addop_post op32

      op8 = dupe[op8]
      op8.name << '.i8'
      addop_post op8

      return
    elsif op.args.first == :regfp0
      dop = dupe[op]
      dop.args.delete :regfp0
      addop_post dop
    end

    if op.props[:needpfx] and @opcode_list.find { |oo| oo.name == op.name and not oo.props[:needpfx] }
      @opcode_list.unshift op
    else
      @opcode_list << op
    end

    if op.args == [:i] or op.args == [:farptr] or op.name[0, 3] == 'ret'
      # define opsz-override version for ambiguous opcodes
      op16 = dupe[op]
      op16.name << '.i16'
      op16.props[:opsz] = 16
      @opcode_list << op16
      op32 = dupe[op]
      op32.name << '.i32'
      op32.props[:opsz] = 32
      @opcode_list << op32
    elsif op.props[:strop] or op.props[:stropz] or op.args.include? :mrm_imm or
        op.args.include? :modrm or op.args.include? :modrmA or op.name =~ /loop|xlat/
      # define adsz-override version for ambiguous opcodes (TODO allow movsd edi / movsd di syntax)
      # XXX loop pfx 67 = eip+cx, 66 = ip+ecx
      op16 = dupe[op]
      op16.name << '.a16'
      op16.props[:adsz] = 16
      @opcode_list << op16
      op32 = dupe[op]
      op32.name << '.a32'
      op32.props[:adsz] = 32
      @opcode_list << op32
    end
  end
end
end
