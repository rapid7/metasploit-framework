#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ppc/main'

module Metasm
class PowerPC
	def addop(name, bin, *argprops)
		o = Opcode.new name, bin 
		o.args.concat(argprops & @fields_mask.keys)
		(argprops & @valid_props).each { |p| o.props[p] = true }
		@opcode_list << o
	end

	# generate l/a variations, add :setip/:saveip, include lr/ctr in opname
	def addop_branch(nbase, bin, *argprops)
		nbase += 'ctr' if argprops.delete :ctr
		nbase += 'lr'  if argprops.delete :lr
		addop(nbase,      bin,   :setip, *argprops)
		addop(nbase+'l',  bin|1, :setip, :saveip, *argprops)
		return if nbase[-2, 2] == 'lr' or nbase[-3, 3] == 'ctr'

		addop(nbase+'a',  bin|2, :setip, *argprops)
		addop(nbase+'la', bin|3, :setip, :saveip, *argprops)
	end

	# generate condition variations, passes to addop_branch
	def addop_branchcond(nbase, bin, *argprops)
		# :bi & 0b11100 is the condition register to use, shift&mask == :bfa. Defaults to cr0
		# bo values
		# no cc (10000 != 0)
		addop_branch(nbase,       bin|(0b10100<<21), :ign_bo_zzz, :stopexec, *argprops)
		addop_branch(nbase+'dz',  bin|(0b10010<<21), :ign_bo_at2, :stopexec, *argprops) if not argprops.include? :ctr
		addop_branch(nbase+'dnz', bin|(0b10000<<21), :ign_bo_at2, :stopexec, *argprops) if not argprops.include? :ctr

		# conditionnal
		%w[lt gt eq so].each_with_index { |cd, i|
			ncd = {'lt' => 'gte', 'gt' => 'lte', 'eq' => 'ne', 'so' => 'nso'}[cd]
			addop_branch(nbase+cd, bin|(0b1100<<21)|(i<<16), :ign_bo_at, *argprops)
			addop_branch(nbase+cd, bin|(0b1100<<21)|(i<<16), :ign_bo_at, :bfa, *argprops)
			addop_branch(nbase+ncd, bin|(0b100<<21)|(i<<16), :ign_bo_at, *argprops)
			addop_branch(nbase+ncd, bin|(0b100<<21)|(i<<16), :ign_bo_at, :bfa, *argprops)
			next if argprops.include? :ctr

			addop_branch(nbase+'dz'+cd,  bin|(0b1010<<21)|(i<<16), :ign_bo_z, *argprops)
			addop_branch(nbase+'dz'+cd,  bin|(0b1010<<21)|(i<<16), :ign_bo_z, :bfa, *argprops)
			addop_branch(nbase+'dnz'+cd, bin|(0b1000<<21)|(i<<16), :ign_bo_z, *argprops)
			addop_branch(nbase+'dnz'+cd, bin|(0b1000<<21)|(i<<16), :ign_bo_z, :bfa, *argprops)
			addop_branch(nbase+'dz'+ncd,  bin|(0b010<<21)|(i<<16), :ign_bo_z, *argprops)
			addop_branch(nbase+'dz'+ncd,  bin|(0b010<<21)|(i<<16), :ign_bo_z, :bfa, *argprops)
			addop_branch(nbase+'dnz'+ncd, bin|(0b000<<21)|(i<<16), :ign_bo_z, *argprops)
			addop_branch(nbase+'dnz'+ncd, bin|(0b000<<21)|(i<<16), :ign_bo_z, :bfa, *argprops)
		}
	end

	# generate cmp variations (default cr0, w/d)
	def addop_cmp(nbase, bin, *argprops)
		addop nbase.sub(/(cmpl?)/, '\\1w'), bin, *(argprops-[:bf])
		addop nbase.sub(/(cmpl?)/, '\\1w'), bin, *argprops
		addop nbase.sub(/(cmpl?)/, '\\1d'), bin|(1<<@fields_shift[:l]), *(argprops-[:bf])
		addop nbase.sub(/(cmpl?)/, '\\1d'), bin|(1<<@fields_shift[:l]), *argprops
	end

	# adds op and 'op.' with last bit of bin set
	def addop_(base, bin, *argprops)
		addop(base, bin, *argprops)
		addop(base+'.', bin|1, *argprops)
	end

	# adds op and 'opo'
	def addop_o(base, bin, *argprops)
		addop(base, bin, *argprops)
		addop(base+'o', bin|0x400, *argprops)
	end

	def init
		@opcode_list = []
		@fields_shift.update :aa => 1, :ba => 16, :bb => 11, :bd => 2, :bf => 23,
			:bfa => 18, :bh => 11, :bt => 21, :d => 0, :dq => 4,
			:ds => 2, :flm => 17, :fra => 16, :frb => 11, :frc => 6, :frs => 21,
			:frt => 21, :fxm => 12, :l => 21, :l_ => 21, :l__ => 16, :lev => 5,
			:li => 2, :lk => 0, :mb => 5, :mb_ => 6, :me => 5, :me_ => 1,
			:nb => 11, :oe => 10, :ra => 16, :rb => 11, :rc => 0, :rs => 21,
			:rt => 21, :sh => 11, :sh_ => 1, :si => 0, :spr => 11, :sr => 16,
			:tbr => 11, :th => 21, :to => 21, :u => 12, :ui => 0,
			:ign_bo_zzz => 16, :ign_bo_z => 21, :ign_bo_at => 21, :ign_bo_at2 => 16

		@fields_mask.update :aa => 1, :ba => 31, :bb => 31, :bd => 0x3FFF, :bf => 7,
			:bfa => 7, :bh => 3, :bt => 31, :d => 0xFFFF, :dq => 0xFFF,
			:ds => 0x3FFF, :flm => 255, :fra => 31, :frb => 31, :frc => 31, :frs => 31,
			:frt => 31, :fxm => 255, :l => 1, :l_ => 3, :l__ => 1, :lev => 127,
			:li => 0xFFFFFF, :lk => 1, :mb => 63, :mb_ => 31, :me => 63, :me_ => 31,
			:nb => 31, :oe => 1, :ra => 31, :rb => 31, :rc => 1, :rs => 31,
			:rt => 31, :sh => 31, :sh_ => 1, :si => 0xFFFF, :spr => 0x3FF, :sr => 15,
			:tbr => 0x3FF, :th => 15, :to => 31, :u => 15, :ui => 0xFFFF,
			:ign_bo_zzz => 0b101111111, :ign_bo_z => 1, :ign_bo_at => 3, :ign_bo_at2 => 0b100111111

		@fields_shift[:ra_i16]  = @fields_shift[:ra_i16s] = @fields_shift[:ra_i16q] = 0
		@fields_mask[:ra_i16]  = (@fields_mask[:d]  << @fields_shift[:d]) | (@fields_mask[:ra] << @fields_shift[:ra])
		@fields_mask[:ra_i16s] = (@fields_mask[:ds] << @fields_shift[:d]) | (@fields_mask[:ra] << @fields_shift[:ra])
		@fields_mask[:ra_i16q] = (@fields_mask[:dq] << @fields_shift[:d]) | (@fields_mask[:ra] << @fields_shift[:ra])


		addop_branch 'b', 0x48000000, :li, :stopexec
		addop_branchcond 'b', 0x40000000, :bd
		addop_branchcond 'b', 0x4C000020, :lr
		addop_branchcond 'b', 0x4C000420, :ctr
	
		addop 'sc',     0x44000002, :lev
		addop 'crand',  0x4C000202, :bt, :ba, :bb
		addop 'crxor',  0x4C000182, :bt, :ba, :bb
	#	alias crclr bx  ->  crxor bx, bx, bx
		addop 'cror',   0x4C000382, :bt, :ba, :bb
	#	alias crmove bx, by  ->  cror bx, by, by
		addop 'crnand', 0x4C0001C2, :bt, :ba, :bb
		addop 'crnor',  0x4C000042, :bt, :ba, :bb
	#	alias crnot bx, by  ->  crnor bx, by, by
		addop 'crandc', 0x4C000102, :bt, :ba, :bb
		addop 'creqv',  0x4C000242, :bt, :ba, :bb
	#	alias crset bx  ->  creqv bx, bx, bx
		addop 'crorc',  0x4C000342, :bt, :ba, :bb
		addop 'mcrf',   0x4C000000, :bf, :bfa
		addop 'lbz',    0x88000000, :rt, :ra_i16
		addop 'lbzu',   0x8C000000, :rt, :ra_i16
		addop 'lbzx',   0x7C0000AE, :rt, :ra, :rb
		addop 'lbzux',  0x7C0000EE, :rt, :ra, :rb
		addop 'lhz',    0xA0000000, :rt, :ra_i16
		addop 'lhzu',   0xA4000000, :rt, :ra_i16
		addop 'lhzx',   0x7C00022E, :rt, :ra, :rb
		addop 'lhzux',  0x7C00026E, :rt, :ra, :rb
		addop 'lha',    0xA8000000, :rt, :ra_i16
		addop 'lhau',   0xAC000000, :rt, :ra_i16
		addop 'lhax',   0x7C0002AE, :rt, :ra, :rb
		addop 'lhaux',  0x7C0002EE, :rt, :ra, :rb
		addop 'lwz',    0x80000000, :rt, :ra_i16
		addop 'lwzu',   0x84000000, :rt, :ra_i16
		addop 'lwzx',   0x7C00002E, :rt, :ra, :rb
		addop 'lwzux',  0x7C00006E, :rt, :ra, :rb
		addop 'lwa',    0xE8000002, :rt, :ra_i16s
		addop 'lwax',   0x7C0002AA, :rt, :ra, :rb
		addop 'lwaux',  0x7C0002EA, :rt, :ra, :rb
		addop 'ld',     0xE8000000, :rt, :ra_i16s
		addop 'ldu',    0xE8000001, :rt, :ra_i16s
		addop 'ldx',    0x7C00002A, :rt, :ra, :rb
		addop 'ldux',   0x7C00006A, :rt, :ra, :rb
		addop 'stb',    0x98000000, :rs, :ra_i16
		addop 'stbu',   0x9C000000, :rs, :ra_i16
		addop 'stbx',   0x7C0001AE, :rs, :ra, :rb
		addop 'stbux',  0x7C0001EE, :rs, :ra, :rb
		addop 'sth',    0xB0000000, :rs, :ra_i16
		addop 'sthu',   0xB4000000, :rs, :ra_i16
		addop 'sthx',   0x7C00032E, :rs, :ra, :rb
		addop 'sthux',  0x7C00036E, :rs, :ra, :rb
		addop 'stw',    0x90000000, :rs, :ra_i16
		addop 'stwu',   0x94000000, :rs, :ra_i16
		addop 'stwx',   0x7C00012E, :rs, :ra, :rb
		addop 'stwux',  0x7C00016E, :rs, :ra, :rb
		addop 'std',    0xF8000000, :rs, :ra_i16s
		addop 'stdu',   0xF8000001, :rs, :ra_i16s
		addop 'stdx',   0x7C00012A, :rs, :ra, :rb
		addop 'stdux',  0x7C00016A, :rs, :ra, :rb
		addop 'lhbrx',  0x7C00062C, :rt, :ra, :rb
		addop 'lwbrx',  0x7C00042C, :rt, :ra, :rb
		addop 'sthbrx', 0x7C00072C, :rs, :ra, :rb
		addop 'stwbrx', 0x7C00052C, :rs, :ra, :rb
		addop 'lmw',    0xB8000000, :rt, :ra_i16
		addop 'stmw',   0xBC000000, :rs, :ra_i16
		addop 'lswi',   0x7C0004AA, :rt, :ra, :nb
		addop 'lswx',   0x7C00042A, :rt, :ra, :rb
		addop 'stswi',  0x7C0005AA, :rs, :ra, :nb
		addop 'stswx',  0x7C00052A, :rs, :ra, :rb
		addop 'li',     0x38000000, :rt, :si					#	alias li rx, value  ->  addi rx, 0, value
		addop 'addi',   0x38000000, :rt, :ra, :si
		addop 'la',     0x38000000, :rt, :ra_i16				#	alias la rx, disp(ry)  ->  addi rx, ry, disp
		addop 'lis',    0x3C000000, :rt, :si					#	alias lis rx, value  ->  addis rx, 0, value
		addop 'addis',  0x3C000000, :rt, :ra, :si
		addop_o 'add',  0x7C000214, :rt, :ra, :rb
		addop 'addic',  0x30000000, :rt, :ra, :si
		addop_o 'sub',  0x7C000050, :rt, :rb, :ra				#	alias sub rx, ry, rz  ->  subf rx, rz, ry
		addop_o 'subf', 0x7C000050, :rt, :ra, :rb
		addop 'addic.', 0x34000000, :rt, :ra, :si
		addop 'subfic', 0x20000000, :rt, :ra, :si
		addop_o 'addc', 0x7C000014, :rt, :ra, :rb
		addop_o 'subc', 0x7C000010, :rt, :rb, :ra				#	alias subc rx, ry, rz  ->  subfc rx, rz, ry
		addop_o 'subfc',0x7C000010, :rt, :ra, :rb
		addop_o 'adde', 0x7C000114, :rt, :ra, :rb
		addop_o 'addme',0x7C0001D4, :rt, :ra
		addop_o 'subfe',0x7C000110, :rt, :ra, :rb
		addop_o 'subfme',0x7C0001D0,:rt, :ra
		addop_o 'addze',0x7C000194, :rt, :ra
		addop_o 'subfze',0x7C000190,:rt, :ra
		addop_o 'neg',  0x7C0000D0, :rt, :ra
		addop 'mulli',  0x1C000000, :rt, :ra, :si
		addop_o 'mulld',0x7C0001D2, :rt, :ra, :rb
		addop_o 'mullw',0x7C0001D6, :rt, :ra, :rb
		addop_ 'mulhd', 0x7C000092, :rt, :ra, :rb
		addop_ 'mulhdu',0x7C000012, :rt, :ra, :rb
		addop_ 'mulhw', 0x7C000096, :rt, :ra, :rb
		addop_ 'mulhwu',0x7C000016, :rt, :ra, :rb
		addop_o 'divd', 0x7C0003D2, :rt, :ra, :rb
		addop_o 'divw', 0x7C0003D6, :rt, :ra, :rb
		addop_o 'divdu',0x7C000392, :rt, :ra, :rb
		addop_o 'divwu',0x7C000396, :rt, :ra, :rb
		addop_cmp 'cmpi',  0x2C000000, :bf, :ra, :si
		addop_cmp 'cmp',   0x7C000000, :bf, :ra, :rb
		addop_cmp 'cmpli', 0x28000000, :bf, :ra, :ui
		addop_cmp 'cmpl',  0x7C000040, :bf, :ra, :rb
		addop 'tdi',    0x08000000, :to, :ra, :si
	#	alias tdlti rx, value  ->  tdi 16, rx, value
	#	alias tdnei rx, value  ->  tdi 24, rx, value
		addop 'twi',    0x0C000000, :to, :ra, :si
	#	alias twgti rx, value  ->  twi 8, rx, value
	#	alias twllei rx, value  ->  twi 6, rx, value
		addop 'td',     0x7C000088, :to, :ra, :rb
	#	alias tdge rx, ry  ->  td 12, rx, ry
	#	alias tdlnl rx, ry  ->  td 5, rx, ry
		addop 'tw',     0x7C000008, :to, :ra, :rb
	#	alias tweq rx, ry  ->  tw 4, rx, ry
	#	alias twlge rx, ry  ->  tw 5, rx, ry
		addop 'andi.',  0x70000000, :ra, :rs, :ui
		addop 'andis.', 0x74000000, :ra, :rs, :ui
		addop 'nop',    0x60000000
		addop 'ori',    0x60000000, :ra, :rs, :ui
		addop 'oris',   0x64000000, :ra, :rs, :ui
		addop 'xori',   0x68000000, :ra, :rs, :ui
		addop 'xoris',  0x6C000000, :ra, :rs, :ui
		addop_ 'and',   0x7C000038, :ra, :rs, :rb
		addop_ 'xor',   0x7C000278, :ra, :rs, :rb
		addop_ 'or',    0x7C000378, :ra, :rs, :rb
	#	alias mr rx, ry  ->  or rx, ry, ry
		addop_ 'nand',  0x7C0003B8, :ra, :rs, :rb
		addop_ 'nor',   0x7C0000F8, :ra, :rs, :rb
	#	alias not rx, ry  ->  nor rx, ry, ry
		addop_ 'andc',  0x7C000078, :ra, :rs, :rb
		addop_ 'eqv',   0x7C000238, :ra, :rs, :rb
		addop_ 'orc',   0x7C000338, :ra, :rs, :rb
		addop_ 'extsb', 0x7C000774, :ra, :rs
		addop_ 'extsw', 0x7C0007B4, :ra, :rs
		addop_ 'extsh', 0x7C000734, :ra, :rs
		addop_ 'cntlzd',0x7C000074, :ra, :rs
		addop_ 'cntlzw',0x7C000034, :ra, :rs
		addop 'popcntb',0x7C0000F4, :ra, :rs
		addop 'clrldi', 0x78000000, :ra, :rs, :mb				#	alias clrldi rx, ry, n  ->  rldicl rx, ry, 0, n
		addop_ 'rldicl',0x78000000, :ra, :rs, :sh, :mb, :sh_
	#	alias extrdi rx, ry, n, b  ->  rldicl rx, ry, b+n, 64 - n
	#	alias srdi rx, ry, n  ->  rldicl rx, ry, 64 - n, n
		addop_ 'rldicr',0x78000004, :ra, :rs, :sh, :me, :sh_
	#	alias extldi rx, ry, n, b  ->  rldicr rx, ry, b, n - 1
	#	alias sldi rx, ry, n  ->  rldicr rx, ry, n, 63 - n
	#	alias clrrdi rx, ry, n  ->  rldicr rx, ry, 0, 63 - n
		addop_ 'rldic', 0x78000008, :ra, :rs, :sh, :mb, :sh_
	#	alias clrlsldi rx, ry, b, n  ->  rldic rx, ry, n, b - n
		addop_ 'rlwinm',0x54000000, :ra, :rs, :sh, :mb_, :me_
	#	alias extlwi rx, ry, n, b  ->  rlwinm rx, ry, b, 0, n - 1
	#	alias srwi rx, ry, n  ->  rlwinm rx, ry, 32 - n, n, 31
	#	alias clrrwi rx, ry, n  ->  rlwinm rx, ry, 0, 0, 31 - n
		addop 'rotld',  0x78000010, :ra, :rs, :rb				#	alias rotld rx, ry, rz  ->  rldcl rx, ry, rz, 0
		addop_ 'rldcl', 0x78000010, :ra, :rs, :rb, :mb
		addop_ 'rldcr', 0x78000012, :ra, :rs, :rb, :me
		addop 'rotlw',  0x5C000000|(31<<@fields_shift[:me_]), :ra, :rs, :rb	#	alias rotlw rx, ry, rz  ->  rlwnm rx, ry, rz, 0, 31
		addop_ 'rlwnm', 0x5C000000, :ra, :rs, :rb, :mb_, :me_
		addop_ 'rldimi',0x7800000C, :ra, :rs, :sh, :mb, :sh_
	#	alias insrdi rx, ry, n, b  ->  rldimi rx, ry, 64 - (b+n), b
		addop_ 'rlwimi',0x50000000, :ra, :rs, :sh, :mb_, :me_
	#	alias inslwi rx, ry, n, b  ->  rlwimi rx, ry, 32-b, b, b+n - 1
		addop_ 'sld',   0x7C000036, :ra, :rs, :rb
		addop_ 'slw',   0x7C000030, :ra, :rs, :rb
		addop_ 'srd',   0x7C000436, :ra, :rs, :rb
		addop_ 'srw',   0x7C000430, :ra, :rs, :rb
		addop_ 'sradi', 0x7C000674, :ra, :rs, :sh, :sh_
		addop_ 'srawi', 0x7C000670, :ra, :rs, :sh
		addop_ 'srad',  0x7C000634, :ra, :rs, :rb
		addop_ 'sraw',  0x7C000630, :ra, :rs, :rb
		#addop 'mtspr', 0x7C0003A6, :spr, :rs
		addop 'mtxer',  0x7C0003A6|(1<<16), :rs
		addop 'mtlr',   0x7C0003A6|(8<<16), :rs
		addop 'mtctr',  0x7C0003A6|(9<<16), :rs
		#addop 'mfspr',  0x7C0002A6, :rt, :spr
		addop 'mfxer',  0x7C0002A6|(1<<16), :rt
		addop 'mflr',   0x7C0002A6|(8<<16), :rt
		addop 'mfctr',  0x7C0002A6|(9<<16), :rt
		addop 'mtcrf',  0x7C000120, :fxm, :rs
	#	alias mtcr rx  ->  mtcrf 0xff, rx
		addop 'mfcr',   0x7C000026, :rt
		addop 'lfs',    0xC0000000, :frt, :ra_i16
		addop 'lfsu',   0xC4000000, :frt, :ra_i16
		addop 'lfsx',   0x7C00042E, :frt, :ra, :rb
		addop 'lfsux',  0x7C00046E, :frt, :ra, :rb
		addop 'lfd',    0xC8000000, :frt, :ra_i16
		addop 'lfdu',   0xCC000000, :frt, :ra_i16
		addop 'lfdx',   0x7C0004AE, :frt, :ra, :rb
		addop 'lfdux',  0x7C0004EE, :frt, :ra, :rb
		addop 'stfs',   0xD0000000, :frs, :ra_i16
		addop 'stfsu',  0xD4000000, :frs, :ra_i16
		addop 'stfsx',  0x7C00052E, :frs, :ra, :rb
		addop 'stfsux', 0x7C00056E, :frs, :ra, :rb
		addop 'stfd',   0xD8000000, :frs, :ra_i16
		addop 'stfdu',  0xDC000000, :frs, :ra_i16
		addop 'stfdx',  0x7C0005AE, :frs, :ra, :rb
		addop 'stfdux', 0x7C0005EE, :frs, :ra, :rb
		addop 'stfiwx', 0x7C0007AE, :frs, :ra, :rb
		addop_ 'fmr',   0xFC000090, :frt, :frb
		addop_ 'fabs',  0xFC000210, :frt, :frb
		addop_ 'fneg',  0xFC000050, :frt, :frb
		addop_ 'fnabs', 0xFC000110, :frt, :frb
		addop_ 'fadd',  0xFC00002A, :frt, :fra, :frb
		addop_ 'fadds', 0xEC00002A, :frt, :fra, :frb
		addop_ 'fsub',  0xFC000028, :frt, :fra, :frb
		addop_ 'fsubs', 0xEC000028, :frt, :fra, :frb
		addop_ 'fmul',  0xFC000032, :frt, :fra, :frc
		addop_ 'fmuls', 0xEC000032, :frt, :fra, :frc
		addop_ 'fdiv',  0xFC000024, :frt, :fra, :frb
		addop_ 'fdivs', 0xEC000024, :frt, :fra, :frb
		addop_ 'fmadd', 0xFC00003A, :frt, :fra, :frc, :frb
		addop_ 'fmadds',0xEC00003A, :frt, :fra, :frc, :frb
		addop_ 'fmsub', 0xFC000038, :frt, :fra, :frc, :frb
		addop_ 'fmsubs',0xEC000038, :frt, :fra, :frc, :frb
		addop_ 'fnmadd',0xFC00003E, :frt, :fra, :frc, :frb
		addop_ 'fnmadds',0xEC00003E,:frt, :fra, :frc, :frb
		addop_ 'fnmsub',0xFC00003C, :frt, :fra, :frc, :frb
		addop_ 'fnmsubs',0xEC00003C,:frt, :fra, :frc, :frb
		addop_ 'frsp',  0xFC000018, :frt, :frb
		addop_ 'fctid', 0xFC00065C, :frt, :frb
		addop_ 'fctidz',0xFC00065E, :frt, :frb
		addop_ 'fctiw', 0xFC00001C, :frt, :frb
		addop_ 'fctiwz',0xFC00001E, :frt, :frb
		addop_ 'fcfid', 0xFC00069C, :frt, :frb
		addop 'fcmpu',  0xFC000000, :bf, :fra, :frb
		addop 'fcmpo',  0xFC000040, :bf, :fra, :frb
		addop_ 'mffs',  0xFC00048E, :frt
		addop 'mcrfs',  0xFC000080, :bf, :bfa
		addop_ 'mtfsfi',0xFC00010C, :bf, :u
		addop_ 'mtfsf', 0xFC00058E, :flm, :frb
		addop_ 'mtfsb0',0xFC00008C, :bt
		addop_ 'mtfsb1',0xFC00004C, :bt
		addop 'mtocrf', 0x7C100120, :fxm, :rs
		addop_ 'fsqrt', 0xFC00002C, :frt, :frb
		addop_ 'fsqrts',0xEC00002C, :frt, :frb
		addop_ 'fre',   0xFC000030, :frt, :frb
		addop_ 'fres',  0xEC000030, :frt, :frb
		addop_ 'frsqrte',0xFC000034,:frt, :frb
		addop_ 'frsqrtes',0xEC000034, :frt, :frb
		addop_ 'fsel',  0xFC00002E, :frt, :fra, :frc, :frb
		addop 'mcrxr',  0x7C000400, :bf
		addop 'icbi',   0x7C0007AC, :ra, :rb
		addop 'dcbt',   0x7C00022C, :ra, :rb
		addop 'dcbtst', 0x7C0001EC, :ra, :rb
		addop 'dcbz',   0x7C0007EC, :ra, :rb
		addop 'dcbst',  0x7C00006C, :ra, :rb
		addop 'dcbf',   0x7C0000AC, :ra, :rb
		addop 'isync',  0x4C00012C
		addop 'lwarx',  0x7C000028, :rt, :ra, :rb
		addop 'ldarx',  0x7C0000A8, :rt, :ra, :rb
		addop 'stwcx.', 0x7C00012D, :rs, :ra, :rb
		addop 'stdcx.', 0x7C0001AD, :rs, :ra, :rb
		addop 'sync',   0x7C0004AC, :l_
		addop 'eieio',  0x7C0006AC
		addop 'mftb',   0x7C0002E6, :rt, :tbr
		addop 'eciwx',  0x7C00026C, :rt, :ra, :rb
		addop 'ecowx',  0x7C00036C, :rs, :ra, :rb
		addop 'dcbt',   0x7C00022C, :ra, :rb, :th
		addop 'dcbf',   0x7C0000AC, :ra, :rb
		addop 'dcbf',   0x7C0000AC, :ra, :rb, :l
		addop 'sc',     0x44000002, :lev
		addop 'rfid',   0x4C000024
		addop 'hrfid',  0x4C000224
		addop 'mtmsrd', 0x7C000164, :rs, :l__
		addop 'mfmsr',  0x7C0000A6, :rt
		addop 'slbie',  0x7C000364, :rb
		addop 'slbmte', 0x7C000324, :rs, :rb
		addop 'slbmfev',0x7C0006A6, :rt, :rb
		addop 'slbmfee',0x7C000726, :rt, :rb
		addop 'tlbie',  0x7C000264, :rb, :l
		addop 'tlbiel', 0x7C000224, :rb, :l
		addop 'tlbia',  0x7C0002E4
		addop 'tlbsync',0x7C00046C
		addop 'mtmsr',  0x7C000124, :rs, :l__
		addop 'lq',     0xE0000000, :rt, :ra_i16q
		addop 'stq',    0xF8000002, :rs, :ra_i16s
		addop 'mtsr',   0x7C0001A4, :sr, :rs
		addop 'mtsrin', 0x7C0001E4, :rs, :rb
		addop 'mfsr',   0x7C0004A6, :rt, :sr
		addop 'mfsrin', 0x7C000526, :rt, :rb

		# pseudo-instructions
		addop 'mr', :pseudo, :ra, :rb
		addop 'not', :pseudo, :ra
		addop 'not', :pseudo, :ra, :rb
		@opcode_list.each { |op|
			if op.name =~ /^addi/
				addop op.name.sub('add', 'sub'), :pseudo, *op.args
			end
			if op.name =~ /^(add|sub|xor|and|or|div|mul|nand)/ and op.args.length == 3
				addop op.name, :pseudo, *op.args[1..-1]
			end
		}
	end
end
end
