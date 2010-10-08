#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/main'
require 'metasm/ia32/opcodes'

module Metasm
class X86_64
	def init_cpu_constants
		super()
		# XXX remove mmx*/fp* ?
		@valid_args.concat [:i32, :u32, :i64, :u64] - @valid_args
	end

	def init_386_common_only
		super()
		@valid_props |= [:imm64, :auto64]
		@opcode_list.delete_if { |o| o.bin[0].to_i & 0xf0 == 0x40 }	# now REX prefix
		@opcode_list.each { |o|
			o.props[:imm64] = true if o.bin == [0xB8]	# mov reg, <true imm64>
			o.props[:auto64] = true if o.name =~ /^(j|loop|(call|enter|leave|lgdt|lidt|lldt|ltr|pop|push|ret)$)/ # operate in 64bit ignoring rex_w
		}
		addop 'movsxd', [0x63], :mrmw
	end

	# all x86_64 cpu understand <= sse2 instrs
	def init_x8664_only
		# TODO XXX mov i64 ?
		# should undef all those
		init_386_common_only
		init_386_only
		# 387 is dead!
		init_486_only
		init_pentium_only
		init_p6_only
		init_sse_only
		init_sse2_only

		@opcode_list.delete_if { |o|
			o.args.include? :modrmmmx or	# mmx is dead!
			o.args.include? :regmmx or	# movd
			o.args.include? :regfp or	# no fpu beyond this line
			o.name == 'loadall' or
			o.name == 'arpl'
		}

		addop 'swapgs',  [0x0F, 0x01, 0xF8]
		addop 'rdtscp',  [0x0F, 0x01, 0xF9]
	end

	def init_sse3
		init_x8664_only
		init_sse3_only
		@opcode_list.delete_if { |o| o.args.include? :modrmmmx }
	end

	def init_vmx
		init_sse3
		init_vmx_only
		@opcode_list.delete_if { |o| o.args.include? :modrmmmx }
	end
	
	def init_all
		init_vmx
		init_sse42_only
		init_3dnow_only
		@opcode_list.delete_if { |o| o.args.include? :modrmmmx }
	end

	alias init_latest init_all


	def addop_macrostr(name, bin, type)
		super(name, bin, type)
		bin = bin.dup
		bin[0] |= 1
		addop(name+'q', bin) { |o| o.props[:opsz] = 64 ; o.props[type] = true }
	end

	def addop_post(op)
		if op.fields[:d] or op.fields[:w] or op.fields[:s]
			return super(op)
		end

		dupe = lambda { |o|
			dop = Opcode.new o.name.dup, o.bin.dup
 			dop.fields, dop.props, dop.args = o.fields.dup, o.props.dup, o.args.dup
			dop
		}

		@opcode_list << op

		if op.args == [:i] or op.args == [:farptr] or op.name[0, 3] == 'ret'
			# define opsz-override version for ambiguous opcodes
			op16 = dupe[op]
			op16.name << '.i16'
			op16.props[:opsz] = 16
			@opcode_list << op16
			# push call ret jz  can't 32bit
			op64 = dupe[op]
			op64.name << '.i64'
			op64.props[:opsz] = 64
			@opcode_list << op64
		elsif op.props[:strop] or op.props[:stropz] or op.args.include? :mrm_imm
			# define adsz-override version for ambiguous opcodes (movsq)
			op32 = dupe[op]
			op32.name << '.a32'
			op32.props[:adsz] = 32
			@opcode_list << op32
			op64 = dupe[op]
			op64.name << '.a64'
			op64.props[:adsz] = 64
			@opcode_list << op64
		end
	end
end
end
