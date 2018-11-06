#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/st20/main'

module Metasm

class ST20
	def init_opcodes
		@op_function = op_get_function
		@op_operate = op_get_operate
		@opcode_list = @op_function.sort.map { |b, n|
			op = Opcode.new(n, b)
			op.props[:setip] = true if n == 'cj'
			op.props[:setip] = op.props[:stopexec] = true if n == 'j'
			op.props[:setip] = op.props[:stopexec] = op.props[:saveip] = true if n == 'fcall'
			op
		}
		@opc_operate = {}
		op = Opcode.new('ret', 0)
		op.props[:setip] = op.props[:stopexec] = true
		@opc_operate['ret'] = op
	end

	def op_get_function
		{
			0x00 => 'j',   0x10 => 'ldlp',  0x20 => 'pfix', 0x30 => 'ldnl',
			0x40 => 'ldc', 0x50 => 'ldnlp', 0x60 => 'nfix', 0x70 => 'ldl',
			0x80 => 'adc', 0x90 => 'fcall', 0xa0 => 'cj',   0xb0 => 'ajw',
			0xc0 => 'eqc', 0xd0 => 'stl',   0xe0 => 'stnl', 0xf0 => 'opr'
		}
	end

	def op_get_operate
		{
			0x00 => 'rev', 0x01 => 'dup', 0x02 => 'rot',       0x03 => 'arot',
			0x04 => 'add', 0x05 => 'sub', 0x06 => 'mul',       0x07 => 'wsub',
			0x08 => 'not', 0x09 => 'and', 0x0A => 'or',        0x0B => 'shl',
			0x0C => 'shr', 0x0D => 'jab', 0x0E => 'timeslice', 0x0F => 'breakpoint',
			0x10 => 'addc',    0x11 => 'subc',     0x12 => 'mac',      0x13 => 'umac',
			0x14 => 'smul',    0x15 => 'smacinit', 0x16 => 'smacloop', 0x17 => 'biquad',
			0x18 => 'divstep', 0x19 => 'unsign',   0x1A => 'saturate', 0x1B => 'gt',
			0x1C => 'gtu',     0x1D => 'order',    0x1E => 'orderu',   0x1F => 'ashr',
			0x20 => 'xor',       0x21 => 'xbword',  0x22 => 'xsword',    0x23 => 'bitld',
			0x24 => 'bitst',     0x25 => 'bitmask', 0x26 => 'statusset', 0x27 => 'statusclr',
			0x28 => 'statustst', 0x29 => 'rmw',     0x2A => 'lbinc',     0x2B => 'sbinc',
			0x2C => 'lsinc',     0x2D => 'lsxinc',  0x2E => 'ssinc',     0x2F => 'lwinc',
			0x30 => 'swinc',    0x31 => 'ecall',   0x32 => 'eret',   0x33 => 'run',
			0x34 => 'stop',     0x35 => 'signal',  0x36 => 'wait',   0x37 => 'enqueue',
			0x38 => 'dequeue',  0x39 => 'ldtdesc', 0x3A => 'ldpi',   0x3B => 'gajw',
			0x3C => 'ldprodid', 0x3D => 'io',      0x3E => 'swap32', 0x3F => 'nop',
		}
	end
end

class TransPuter
	def op_get_operate
		{
			0x00 => 'rev',  0x01 => 'lb',     0x02 => 'bsub',    0x03 => 'endp',
			0x04 => 'diff', 0x05 => 'add',    0x06 => 'gcall',   0x07 => 'in',
			0x08 => 'prod', 0x09 => 'gt',     0x0a => 'wsub',    0x0b => 'out',
			0x0c => 'sub',  0x0d => 'startp', 0x0e => 'outbyte', 0x0f => 'outword',
			0x10 => 'seterr',  0x11 => 'mreleasep', 0x12 => 'resetch', 0x13 => 'csub0',
			0x14 => 'extvrfy', 0x15 => 'stopp',     0x16 => 'ladd',    0x17 => 'stlb',
			0x18 => 'sthf',    0x19 => 'norm',      0x1a => 'ldiv',    0x1b => 'ldpi',
			0x1c => 'stlf',    0x1d => 'xdble',     0x1e => 'ldpri',   0x1f => 'rem',
			0x20 => 'ret',     0x21 => 'lend',         0x22 => 'ldtimer',    0x23 => 'testlds',
			0x24 => 'testlde', 0x25 => 'testldd',      0x26 => 'teststs',    0x27 => 'testste',
			0x28 => 'teststd', 0x29 => 'testerr',      0x2a => 'testpranal', 0x2b => 'tin',
			0x2c => 'div',     0x2d => 'testhardchan', 0x2e => 'dist',       0x2f => 'disc',
			0x30 => 'diss', 0x31 => 'lmul',  0x32 => 'not',   0x33 => 'xor',
			0x34 => 'bcnt', 0x35 => 'lshr',  0x36 => 'lshl',  0x37 => 'lsum',
			0x38 => 'lsub', 0x39 => 'runp',  0x3a => 'xword', 0x3b => 'sb',
			0x3c => 'gajw', 0x3d => 'savel', 0x3e => 'saveh', 0x3f => 'wcnt',
			0x40 => 'shr',   0x41 => 'shl',    0x42 => 'mint', 0x43 => 'alt',
			0x44 => 'altwt', 0x45 => 'altend', 0x46 => 'and',  0x47 => 'enbt',
			0x48 => 'enbc',  0x49 => 'enbs',   0x4a => 'move', 0x4b => 'or',
			0x4c => 'csngl', 0x4d => 'ccnt1',  0x4e => 'talt', 0x4f => 'ldiff',
			0x50 => 'sthb',       0x51 => 'taltwt',        0x52 => 'sum',        0x53 => 'mul',
			0x54 => 'sttimer',    0x55 => 'stoperr',       0x56 => 'cword',      0x57 => 'clrhalterr',
			0x58 => 'sethalterr', 0x59 => 'testhalterr',   0x5a => 'dup',        0x5b => 'move2dinit',
			0x5c => 'move2dall',  0x5d => 'move2dnonzero', 0x5e => 'move2dzero', 0x5f => 'gtu',
			0x60 => 'extin',      0x61 => 'extout',  0x62 => 'minn',     0x63 => 'unpacksn',
			0x64 => 'moutn',      0x65 => 'xminn',   0x66 => 'extenbc',  0x67 => 'extndisc',
			0x68 => 'extmin',     0x69 => 'extmout', 0x6a => 'extmin64', 0x6b => 'extmout64',
			0x6c => 'postnormsn', 0x6d => 'roundsn', 0x6e => 'extminn',  0x6f => 'extmoutn',
			0x70 => 'enbc3',        0x71 => 'ldinf',        0x72 => 'fmul',          0x73 => 'cflerr',
			0x74 => 'crcword',      0x75 => 'crcbyte',      0x76 => 'bitcnt',        0x77 => 'bitrevword',
			0x78 => 'bitrevnbits',  0x79 => 'pop',          0x7a => 'timerdisableh', 0x7b => 'timerdisablel',
			0x7c => 'timerenableh', 0x7d => 'timerenablel', 0x7e => 'ldmemstartval', 
			0x80 => 'fpsttest', 0x81 => 'wsubdb',   0x82 => 'fpldnldbi', 0x83 => 'fpchkerr',
			0x84 => 'fpstnldb', 0x85 => 'fpldtest', 0x86 => 'fpldnlsni', 0x87 => 'fpadd',
			0x88 => 'fpstnlsn', 0x89 => 'fpsub',    0x8a => 'fpldnldb',  0x8b => 'fpmul',
			0x8c => 'fpdiv',    0x8d => 'fprange',  0x8e => 'fpldnlsn',  0x8f => 'fpremfirst',
			0x90 => 'fpremstep',  0x91 => 'fpnan',    0x92 => 'fpordered',  0x93 => 'fpnotfinite',
			0x94 => 'fpgt',       0x95 => 'fpeq',     0x96 => 'fpi32tor32', 0x97 => 'fpge',
			0x98 => 'fpi32tor64', 0x99 => 'enbt3',    0x9a => 'fpb32tor64', 0x9b => 'fplg',
			0x9c => 'fptesterr',  0x9d => 'fprtoi32', 0x9e => 'fpstnli32',  0x9f => 'fpldzerosn',
			0xa0 => 'fpldzerodb',  0xa1 => 'fpint',    0xa2 => 'getpri',      0xa3 => 'fpdup',
			0xa4 => 'fprev',       0xa5 => 'setpri',   0xa6 => 'fpldnladddb', 0xa7 => 'fpentry3',
			0xa8 => 'fpldnlmuldb', 0xa9 => 'fpentry2', 0xaa => 'fpldnladdsn', 0xab => 'fpentry',
			0xac => 'fpldnlmulsn', 0xad => 'enbs3', 
			0xb0 => 'settimeslice', 0xb1 => 'break',   0xb2 => 'clrj0break', 0xb3 => 'setj0break',
			0xb4 => 'testj0break',                     0xb6 => 'ldflags',    0xb7 => 'stflags',
			0xb8 => 'xbword',       0xb9 => 'lbx',     0xba => 'cb',         0xbb => 'cbu',
			0xbc => 'insphdr',      0xbd => 'readbfr', 0xbe => 'ldconf',     0xbf => 'stconf',
			0xc0 => 'ldcnt',  0xc1 => 'ssub',     0xc2 => 'ldth',      0xc3 => 'ldchstatus',
			0xc4 => 'intdis', 0xc5 => 'intenb',   0xc6 => 'ldtrapped', 0xc7 => 'cir',
			0xc8 => 'ss',     0xc9 => 'chantype', 0xca => 'ls',        0xcb => 'sttrapped',
			0xcc => 'ciru',   0xcd => 'gintdis',  0xce => 'gintenb',   0xcf => 'fprem',
			0xd0 => 'fprn',       0xd1 => 'fpdivby2',   0xd2 => 'fpmulby2',   0xd3 => 'fpsqrt',
			0xd4 => 'fprp',       0xd5 => 'fprm',       0xd6 => 'fprz',       0xd7 => 'fpr32tor64',
			0xd8 => 'fpr64tor32', 0xd9 => 'fpexpdec32', 0xda => 'fpexpinc32', 0xdb => 'fpabs',
			                      0xdd => 'fpadddbsn',  0xde => 'fpchki32',   0xdf => 'fpchki64',
			0xe0 => 'mnew',  0xe1 => 'mfree', 0xe2 => 'malloc', 0xe3 => 'mrelease',
			0xe4 => 'min',   0xe5 => 'mout',  0xe6 => 'min64',  0xe7 => 'mout64',
			0xe8 => 'xable', 0xe9 => 'xin',   0xea => 'xmin',   0xeb => 'xmin64',
			0xec => 'xend',  0xed => 'ndisc', 0xee => 'ndist',  0xef => 'ndiss',
			0xf0 => 'devlb', 0xf1 => 'devsb', 0xf2 => 'devls',  0xf3 => 'devss',
			0xf4 => 'devlw', 0xf5 => 'devsw', 0xf8 => 'xsword', 0xf9 => 'lsx',
			0xfa => 'cs',    0xfb => 'csu',   0xfc => 'trap',   0xfd => 'null',
			0x1ff => 'start',
			0x17c => 'lddevid',
			0x200 => 'in8', 0x201 => 'in32', 0x202 => 'out8', 0x203 => 'out32',
			0x204 => 'xstl',
			0x22f => 'proc_alloc',
			0x230 => 'proc_param', 0x231 => 'proc_mt_copy', 0x232 => 'proc_mt_move', 0x233 => 'proc_start',
			0x234 => 'proc_end',   0x235 => 'getaff',       0x236 => 'setaff',       0x237 => 'getpas',
			0x238 => 'mt_alloc',   0x239 => 'mt_release',   0x23a => 'mt_clone',     0x23b => 'mt_in',
			0x23c => 'mt_out',     0x23d => 'mt_xchg',      0x23e => 'mt_lock',      0x23f => 'mt_unlock',
			0x240 => 'mt_enroll',  0x241 => 'mt_resign', 0x242 => 'mt_sync',   0x243 => 'mt_xin',
			0x244 => 'mt_xout',    0x245 => 'mt_xxchg',  0x246 => 'mt_dclone', 0x247 => 'mt_bind',
			0x248 => 'mb',         0x249 => 'rmb',       0x24a => 'wmb',       0x24b => 'ext_mt_in',
			0x24c => 'ext_mt_out', 0x24d => 'mt_resize',
		}
	end
end
end
