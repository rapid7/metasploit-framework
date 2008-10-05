#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'


module Metasm

# holds information for decoded instructions: the original opcode, a pointer to the InstructionBlock, etc
class DecodedInstruction
	# the instance of InstructionBlock this di is into
	attr_accessor :block
	# our offset (in bytes) from the start of the block, used only for hexdump
	attr_accessor :block_offset
	# the address of the instruction's first byte in memory
	attr_accessor :address
	# the disassembled data
	attr_accessor :instruction, :opcode
	# our, length in bytes
	attr_accessor :bin_length
	# array of arbitrary strings
	attr_accessor :comment
	# a cache of the binding used by the backtracker to emulate this instruction
	attr_accessor :backtrace_binding

	def initialize(cpu)
		@instruction = Instruction.new cpu
		@bin_length = 0
	end

	def next_addr
		address + @bin_length
	end

	def block_head?
		self == @block.list.first
	end

	def show
		if block
			bin = @block.edata.data[@block.edata_ptr+@block_offset, @bin_length].unpack('C*').map { |c| '%02x' % c }.join
			if @bin_length > 12
				bin = bin[0, 20] + "..<+#{@bin_length-10}>"
			end
			"    #{@instruction.to_s.ljust(44)} ; @#{Expression[address]}  #{bin}  #{@comment.sort[0,6].join(' ') if comment}"
		else
			"#{@instruction}#{' ; ' + @comment.join(' ') if comment}"
		end
	end

	def to_s
		"#{Expression[address] if block} #{@instruction}"
	end

	def add_comment(c)
		@comment ||= []
		@comment |= [c]
	end
end

# holds information on a backtracked expression near begin and end of instruction blocks (#backtracked_for)
class BacktraceTrace
	# address of the instruction in the block from which rebacktrace should start (use with from_subfuncret bool)
	# address is nil if the backtrace is from block start
	# exclude_instr is a bool saying if the backtrace should start at address or at the preceding instruction
	# these are optional: if absent, expr is to be rebacktracked when a new codepath arrives at the beginning of the block
	attr_accessor :address, :from_subfuncret, :exclude_instr
	# address of the instruction that initiated the backtrace
	attr_accessor :origin
	# the Expression to backtrace at this point
	attr_accessor :expr
	# the original backtracked Expression
	attr_accessor :orig_expr
	# length of r/w xref (in bytes)
	attr_accessor :len
	# :r/:w/:x
	attr_accessor :type
	# bool: true if this maps to a :x that should not have a from when resolved
	attr_accessor :detached
	# maxdepth at the point of the object creation
	attr_accessor :maxdepth

	def initialize(expr, origin, orig_expr, type, len=nil, maxdepth=nil)
		@expr, @origin, @orig_expr, @type = expr, origin, orig_expr, type
		@len = len if len
		@maxdepth = maxdepth if maxdepth
	end

	def hash ; [origin, expr].hash ; end
	def eql?(o)
		o.class == self.class and
		[  address,   from_subfuncret,   exclude_instr,   origin,   orig_expr,   len,   type,   detached] ==
		[o.address, o.from_subfuncret, o.exclude_instr, o.origin, o.orig_expr, o.len, o.type, o.detached]
	end
	alias == eql?
end

# a cross-reference, tracks read/write/execute memory accesses by decoded instructions
class Xref
	# :r/:w/:x
	attr_accessor :type
	# length of r/w (in bytes)
	attr_accessor :len
	# address of the instruction responsible of the xref
	attr_accessor :origin
	# XXX list of instructions intervening in the backtrace ?

	def initialize(type, origin, len=nil)
		@origin, @type = origin, type
		@len = len if len
	end

	def hash ; @origin.hash ; end
	def eql?(o) o.class == self.class and [type, len, origin] == [o.type, o.len, o.origin] end
	alias == eql?
end

# holds a list of contiguous decoded instructions, forming an uninterrupted block (except for eg CPU exceptions)
# most attributes are either a value or an array of values, use the associated iterator.
class InstructionBlock
	# address of the first instruction
	attr_accessor :address
	# pointer to raw data
	attr_accessor :edata, :edata_ptr
	# list of DecodedInstructions
	attr_accessor :list
	# address of instructions giving control directly to us
	# includes addr of normal instruction when call flow continues to us past the end of the preceding block
	# does not include addresses of subfunction return instructions
	# may be nil or an array
	attr_accessor :from_normal
	# address of instructions called/jumped to
	attr_accessor :to_normal
	# address of an instruction that calls a subfunction which returns to us
	attr_accessor :from_subfuncret
	# address of instruction executed after a called subfunction returns
	attr_accessor :to_subfuncret
	# address of instructions executed indirectly through us (callback in a subfunction, SEH...)
	# XXX from_indirect is not populated for now
	attr_accessor :from_indirect, :to_indirect
	# array of BacktraceTrace
	# when a new code path comes to us, it should be backtracked for the values of :r/:w/:x using btt with no address
	# for internal use only (block splitting): btt with an address
	attr_accessor :backtracked_for

	def initialize(address, edata, edata_ptr=edata.ptr)
		@address = address
		@edata, @edata_ptr = edata, edata_ptr
		@list = []
		@backtracked_for = []
	end

	def bin_length
		(di = @list.last) ? di.block_offset + di.bin_length : 0
	end
	
	# splits the current block into a new one with all di from address addr to end
	# caller is responsible for rebacktracing new.bt_for to regenerate correct old.btt/new.btt
	def split(addr)
		raise "invalid split #{addr}" if not idx = @list.index(@list.find { |di| di.address == addr }) or idx == 0
		off = @list[idx].block_offset
		new_b = self.class.new(addr, @edata, @edata_ptr + off)
		new_b.add_di @list.delete_at(idx) while @list[idx]
		new_b.to_normal, @to_normal = to_normal, new_b.to_normal
		new_b.to_subfuncret, @to_subfuncret = to_subfuncret, new_b.to_subfuncret
		new_b.add_from @list.last.address
		add_to new_b.address
		@backtracked_for.delete_if { |btt|
			if btt.address and new_b.list.find { |di| di.address == btt.address }
				new_b.backtracked_for << btt
				true
			end
		}
		new_b
	end

	# adds a decodedinstruction to the block list, updates di.block and di.block_offset
	def add_di(di)
		di.block = self
		di.block_offset = bin_length
		di.address ||= @address + di.block_offset
		@list << di
	end

	# adds an address to the from_normal/from_subfuncret list
	def add_from(addr, type=:normal)
		send "add_from_#{type}", addr
	end
	def add_from_normal(addr)
		@from_normal ||= []
		@from_normal |= [addr]
	end
	def add_from_subfuncret(addr)
		@from_subfuncret ||= []
		@from_subfuncret |= [addr]
	end
	def add_from_indirect(addr)
		@from_indirect ||= []
		@from_indirect |= [addr]
	end
	# iterates over every from address, yields [address, type in [:normal, :subfuncret, :indirect]]
	def each_from
		each_from_normal { |a| yield a, :normal }
		each_from_subfuncret { |a| yield a, :subfuncret }
		each_from_indirect { |a| yield a, :indirect }
	end
	def each_from_normal(&b)
		@from_normal.each(&b) if from_normal
	end
	def each_from_subfuncret(&b)
		@from_subfuncret.each(&b) if from_subfuncret
	end
	def each_from_indirect(&b)
		@from_indirect.each(&b) if from_indirect
	end

	def add_to(addr, type=:normal)
		send "add_to_#{type}", addr
	end
	def add_to_normal(addr)
		@to_normal ||= []
		@to_normal |= [addr]
	end
	def add_to_subfuncret(addr)
		@to_subfuncret ||= []
		@to_subfuncret |= [addr]
	end
	def add_to_indirect(addr)
		@to_indirect ||= []
		@to_indirect |= [addr]
	end
	def each_to
		each_to_normal     { |a| yield a, :normal }
		each_to_subfuncret { |a| yield a, :subfuncret }
		each_to_indirect   { |a| yield a, :indirect }
	end
	def each_to_normal(&b)
		@to_normal.each(&b) if to_normal
	end
	def each_to_subfuncret(&b)
		@to_subfuncret.each(&b) if to_subfuncret
	end
	def each_to_indirect(&b)
		@to_indirect.each(&b) if to_indirect
	end

	def each_from_samefunc(dasm, &b)
		return if dasm.function[address]
		@from_subfuncret.each(&b) if from_subfuncret
		@from_normal.each(&b) if from_normal
	end

	# yields all from that are not in the same subfunction as this block
	def each_from_otherfunc(dasm, &b)
		@from_normal.each(&b) if from_normal and dasm.function[address]
		@from_subfuncret.each(&b) if from_subfuncret and dasm.function[address]
		@from_indirect.each(&b) if from_indirect
	end

	# yields all to that are in the same subfunction as this block
	def each_to_samefunc(dasm)
		each_to { |to, type|
			next if type != :normal and type != :subfuncret
			to = dasm.normalize(to)
			yield to if not dasm.function[to]
		}
	end

	# yields all to that are not in the same subfunction as this block
	def each_to_otherfunc(dasm)
		each_to { |to, type|
			to = dasm.normalize(to)
			yield to if type == :indirect or dasm.function[to]
		}
	end
end

# a factorized subfunction as seen by the disassembler
class DecodedFunction
	# when backtracking an instruction that calls us, use this binding and then the instruction's
	attr_accessor :backtrace_binding
	# same as InstructionBlock#backtracked_for
	# includes the expression responsible of the function return (eg [esp] on ia32)
	attr_accessor :backtracked_for
	# addresses of instruction causing the function to return
	attr_accessor :return_address
	# a proc called for dynamic backtrace_binding generation
	# XXX TODO handle propagation (eg GetProcAddress thunk)
	attr_accessor :btbind_callback
	# a proc called for dynamic backtracked_for
	attr_accessor :btfor_callback
	# bool, if true the full function binding is incomplete
	attr_accessor :need_finalize

	# if btbind_callback is defined, calls it with args [dasm, binding, funcaddr, calladdr, expr, origin, maxdepth]
	# else return backtrace_binding
	def get_backtrace_binding(dasm, funcaddr, calladdr, expr, origin, maxdepth)
		if btbind_callback
			@btbind_callback[dasm, @backtrace_binding, funcaddr, calladdr, expr, origin, maxdepth]
		else
			@backtrace_binding
		end
	end

	# if btfor_callback is defined, calls it with args [dasm, bt_for, funcaddr, calladdr]
	# else return backtracked_for
	def get_backtracked_for(dasm, funcaddr, calladdr)
		if btfor_callback
			@btfor_callback[dasm, @backtracked_for, funcaddr, calladdr]
		else
			@backtracked_for
		end
	end

	def initialize
		@backtracked_for = []
		@backtrace_binding = {}
	end
end

# symbolic pointer dereference
# API similar to Expression
class Indirection < ExpressionType
	# Expression (the pointer)
	attr_accessor :target
	# length in bytes of data referenced
	attr_accessor :len
	# address of the instruction who generated the indirection
	attr_accessor :origin

	def initialize(target, len, origin)
		@target, @len, @origin = target, len, origin
	end

	def reduce_rec
		ptr = Expression[@target.reduce]
		(ptr == Expression::Unknown) ? ptr : Indirection.new(ptr, @len, @origin)
	end

	def bind(h)
		h[self] || Indirection.new(@target.bind(h), @len, @origin)
	end

	def hash ; @target.hash^@len end
	def eql?(o) o.class == self.class and [o.target, o.len] == [@target, @len] end
	alias == eql?

	def to_s
		qual = {1 => 'byte', 2 => 'word', 4 => 'dword'}[@len] || "_#{len*8}bits"
		"#{qual} ptr [#{target}]"
	end

	# returns the complexity of the expression (number of externals +1 per indirection)
	def complexity
		1+@target.complexity
	end

	def self.[](t, l, o=nil)
		new(Expression[*t], l, o)
	end

	def inspect
		"Indirection[#{@target.inspect.sub(/^Expression/, '')}, #{@len.inspect}#{', '+@origin.inspect if @origin}]"
	end

	def externals
		@target.externals
	end

	def match_rec(target, vars)
		return false if not target.kind_of? Indirection
		t = target.target
		if vars[t]
			return false if @target != vars[t]
		elsif vars.has_key? t
			vars[t] = @target
		elsif t.kind_of? ExpressionType
			return false if not @target.match_rec(t, vars)
		else
			return false if targ != @target
		end
		if vars[target.len]
			return false if @len != vars[target.len]
		elsif vars.has_key? target.len
			vars[target.len] = @len
		else
			return false if target.len != @len
		end
		vars
	end
end

class Expression
	# returns the complexity of the expression (number of externals +1 per indirection)
	def complexity
		case @lexpr
		when ExpressionType; @lexpr.complexity
		when nil, ::Numeric; 0
		else 1
		end +
		case @rexpr
		when ExpressionType; @rexpr.complexity
		when nil, ::Numeric; 0
		else 1
		end
	end

	def expr_indirections
		ret = case @lexpr
		when Indirection; [@lexpr]
		when ExpressionType; @lexpr.expr_indirections
		else []
		end
		case @rexpr
		when Indirection; ret << @rexpr
		when ExpressionType; ret.concat @rexpr.expr_indirections
		else ret
		end
	end
end

class EncodedData
	# returns an ::Integer from self.ptr, advances ptr
	# bytes from rawsize to virtsize = 0
	# ignores self.relocations
	def get_byte
		@ptr += 1
		if @ptr <= @data.length
			@data[ptr-1]
		elsif @ptr <= @virtsize
			0
		end
	end

	# reads len bytes from self.data, advances ptr
	# bytes from rawsize to virtsize are returned as zeroes
	# ignores self.relocations
	def read(len=@virtsize-@ptr)
		len = @virtsize-@ptr if len > @virtsize-@ptr
		str = (@ptr < @data.length) ? @data[@ptr, len] : ''
		str = str.ljust(len, "\0") if str.length < len
		@ptr += len
		str
	end
	
	# decodes an immediate value from self.ptr, advances ptr
	# returns an Expression on relocation, or an ::Integer
	# if ptr has a relocation but the type/endianness does not match, the reloc is ignored and a warning is issued
	# TODO arg type => sign+len
	def decode_imm(type, endianness)
		if rel = @reloc[@ptr]
			if Expression::INT_SIZE[rel.type] == Expression::INT_SIZE[type] and rel.endianness == endianness
				@ptr += rel.length
				return rel.target
			end
			puts "W: Immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect} (wanted #{type.inspect})" if $DEBUG
		end
		Expression.decode_imm(read(Expression::INT_SIZE[type]/8), type, endianness)
	end
end

class Expression
	def self.decode_imm(str, type, endianness)
                val = 0
                case endianness
                when :little; str.reverse
		when :big; str
		end.unpack('C*').each { |b| val = (val << 8) | b }
		val = val - (1 << (INT_SIZE[type])) if type.to_s[0] == ?i and val >> (INT_SIZE[type]-1) == 1	# XXX booh
		val
	end

end
class CPU
	# decodes the instruction at edata.ptr, mapped at virtual address off
	# returns a DecodedInstruction or nil
	def decode_instruction(edata, addr)
		@bin_lookaside ||= build_bin_lookaside
		di = decode_findopcode edata
		di = decode_instr_op(edata, di) if di
		decode_instr_interpret(di, addr) if di
	end

	# matches the binary opcode at edata.ptr
	# returns di or nil
	def decode_findopcode(edata)
		DecodedInstruction.new self
	end

	# decodes di.instruction
	# returns di or nil
	def decode_instr_op(edata, di)
	end

	# may modify di.instruction.args for eg jump offset => absolute address
	# returns di or nil
	def decode_instr_interpret(di, addr)
		di
	end

	# return the thing to backtrace to find +value+ before the execution of this instruction
	# eg backtrace_emu('inc eax', Expression[:eax]) => Expression[:eax + 1]
	#  (the value of :eax after 'inc eax' is the value of :eax before plus 1)
	# may return Expression::Unknown
	def backtrace_emu(di, value)
		Expression[Expression[value].bind(di.backtrace_binding ||= backtrace_binding(di)).reduce]
	end

	# returns a list of Expressions/Integer to backtrace to find an execution target
	def get_xrefs_x(dasm, di)
	end

	# returns a list of [type, address, len]
	def get_xrefs_rw(dasm, di)
		get_xrefs_r(dasm, di).map { |addr, len| [:r, addr, len] } + get_xrefs_w(dasm, di).map { |addr, len| [:w, addr, len] }
	end

	# returns a list [addr, len]
	def get_xrefs_r(dasm, di)
		b = di.backtrace_binding ||= backtrace_binding(di)
		r = b.values
		x = get_xrefs_x(dasm, di)
		r |= x if x
		(r.grep(Indirection) + r.grep(Expression).map { |e| e.expr_indirections }.flatten).map { |e| [e.target, e.len] }
	end

	# returns a list [addr, len]
	def get_xrefs_w(dasm, di)
		b = di.backtrace_binding ||= backtrace_binding(di)
		w = b.keys
		(w.grep(Indirection) + w.grep(Expression).map { |e| e.expr_indirections }.flatten).map { |e| [e.target, e.len] }
	end

	# checks if the expression corresponds to a function return value with the instruction
	# (eg di == 'call something' and expr == [esp])
	def backtrace_is_function_return(expr, di=nil)
	end

	# updates f.backtrace_binding when a new return address has been found
	# TODO update also when anything changes inside the function (new loop found etc) - use backtracked_for ?
	def backtrace_update_function_binding(dasm, faddr, f, retaddrlist)
	end

	# returns if the expression is an address on the stack
	# (to avoid trying to backtrace its absolute address until we found function boundaries)
	def backtrace_is_stack_address(expr)
	end

	# updates the instruction arguments: replace an expression with another (eg when a label is renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression; Expression[a.bind(old => new).reduce]
			else a
			end
		}
	end

	# a callback called whenever a backtrace is successful
	# di is the decodedinstruction at the backtrace's origin
	def backtrace_found_result(dasm, di, expr, type, len)
	end

	# number of instructions following a jump that are still executed
	def delay_slot(di)
		0
	end
end

class ExeFormat
	# returns a string containing asm-style section declaration
	def dump_section_header(addr, edata)
		"\n// section at #{Expression[addr]}"
	end

	# returns an array of expressions that may be executed by this instruction
	def get_xrefs_x(dasm, di)  @cpu.get_xrefs_x(dasm, di)  end

	# returns an array of [type, expression, length] that may be accessed by this instruction (type is :r/:w, len is in bytes)
	def get_xrefs_rw(dasm, di) @cpu.get_xrefs_rw(dasm, di) end
end

# a disassembler class
# holds a copy of a program sections, a list of decoded instructions, xrefs
# is able to backtrace an expression from an address following the call flow (backwards)
class Disassembler
	attr_accessor :program, :cpu
	# binding (jointure of @sections.values.exports)
	attr_accessor :prog_binding
	# hash addr => edata
	attr_accessor :sections
	# hash addr => DecodedInstruction
	attr_accessor :decoded
	# hash addr => DecodedFunction	 (includes 'imported' functions)
	attr_accessor :function
	# hash addr => (array of) xrefs - access with +add_xref+/+each_xref+
	attr_accessor :xrefs
	# bool, true to check write xrefs on each instr disasm (default true)
	attr_accessor :check_smc
	# list of [addr to disassemble, (optional)who jumped to it, (optional)got there by a subfunction return]
	attr_accessor :addrs_todo 
	# hash address => binding
	attr_accessor :address_binding
	# number of blocks to backtrace before aborting if no result is found (defaults to class.backtrace_maxblocks, 50 by default)
	attr_accessor :backtrace_maxblocks
	# maximum backtrace length for :r/:w, defaults to backtrace_maxblocks
	attr_accessor :backtrace_maxblocks_data
	# a cparser that parsed some C header files, prototypes are converted to DecodedFunction when jumped to
	attr_accessor :c_parser
	# hash address => array of strings
	# default dasm dump will only show comments at beginning of code blocks
	attr_accessor :comment
	# bool, set to true (default) if functions with undetermined binding should be assumed to return with ABI-conforming binding (conserve frame ptr)
	attr_accessor :funcs_stdabi
	# callback called whenever a new address is to be appended to the list of addresses to disassemble (except subfunction returns)
	# this method must return the address to append ; or nil if no address is to be appended.
	# it is invoked with arguments (target address found, address of origininating instruction)
	attr_accessor :callback_newaddr

	@@backtrace_maxblocks = 50
	def self.backtrace_maxblocks ; @@backtrace_maxblocks ; end
	def self.backtrace_maxblocks=(b) ; @@backtrace_maxblocks = b ; end


	# parses a C header file, from which function prototypes will be converted to DecodedFunction when found in the code flow
	def parse_c_file(file)
		parse_c File.read(file)
	end

	# parses a C string for function prototypes
	def parse_c(str)
		@c_parser ||= @cpu.new_cparser
		@c_parser.parse(str)
	end

	# creates a new disassembler
	def initialize(program, cpu=program.cpu)
		@program = program
		@cpu = cpu
		@sections = {}
		@decoded = {}
		@xrefs = {}
		@function = {}
		@check_smc = true
		@prog_binding = {}
		@old_prog_binding = {}
		@addrs_todo = []
		@address_binding = {}
		@backtrace_maxblocks = @@backtrace_maxblocks
		@comment = {}
		@funcs_stdabi = true
	end

	# adds a section, updates prog_binding
	# base addr is an Integer or a String (label name for offset 0)
	def add_section(encoded, base)
		case base
		when ::Integer
		when ::String
			raise "invalid section base #{base.inspect} - not at section start" if encoded.export[base] and encoded.export[base] != 0
			raise "invalid section base #{base.inspect} - already seen at #{@prog_binding[base]}" if @prog_binding[base] and @prog_binding[base] != Expression[base]
			encoded.add_export base, 0
		else raise "invalid section base #{base.inspect} - expected string or integer"
		end

		@sections[base] = encoded
		encoded.binding(base).each { |k, v|
			@prog_binding[k] = v.reduce
		}
		self
	end

	def add_xref(addr, x)
		case @xrefs[addr]
		when nil; @xrefs[addr] = x
		when x
		when ::Array; @xrefs[addr] |= [x]
		else @xrefs[addr] = [@xrefs[addr], x]
		end
	end

	# yields each xref to a given address, optionnaly restricted to a type
	def each_xref(addr, type=nil)
		addr = normalize addr
		case @xrefs[addr]
		when nil
		when ::Array; @xrefs[addr].each { |x| yield x if not type or x.type == type }
		else yield @xrefs[addr] if not type or @xrefs[addr].type == type
		end
	end

	def each_instructionblock
		@decoded.sort.each { |addr, di| yield di.block if di.kind_of? DecodedInstruction and di.block.list.first == di }
	end

	# returns the canonical form of addr (absolute address integer or label of start of section + section offset)
	def normalize(addr)
		return addr if not addr or addr == :default
		Expression[addr].bind(@old_prog_binding).bind(@prog_binding).reduce
	end

	# returns [edata, edata_base] or nil
	# edata.ptr points to addr
	def get_section_at(addr)
		case addr = normalize(addr)
		when ::Integer
			if s =  @sections.find { |b, e| b.kind_of? ::Integer and addr >= b and addr < b + e.length } ||
				@sections.find { |b, e| b.kind_of? ::Integer and addr == b + e.length }		# end label
				s[1].ptr = addr - s[0]
				[s[1], s[0]]
			end
		when Expression
			if addr.op == :+ and addr.rexpr.kind_of? ::Integer and addr.lexpr.kind_of? ::String and e = @sections[addr.lexpr]
				e.ptr = addr.rexpr
				[e, Expression[addr.lexpr]]
			elsif addr.op == :+ and addr.rexpr.kind_of? ::String and not addr.lexpr and e = @sections[addr]
				e.ptr = 0
				[e, addr]
			end
		end
	end

	# returns the label at the specified address, creates it if needed using "prefix_addr"
	# renames the existing label if it is in the form rewritepfx_addr
	# returns nil if the address is not known and is not a string
	def auto_label_at(addr, base='xref', *rewritepfx)
		addr = Expression[addr].reduce
		addrstr = "#{base}_#{Expression[addr]}"
		e, b = get_section_at(addr)
		if not e
			l = Expression[addr].reduce_rec if Expression[addr].reduce_rec.kind_of? ::String
			l ||= addrstr if addr.kind_of? Expression and addr.externals.grep(::Symbol).empty?
		elsif not l = e.inv_export[e.ptr]
			l = @program.new_label(addrstr)
			e.add_export l, e.ptr
			@prog_binding[l] = b + e.ptr
		elsif rewritepfx.find { |p| base != p and addrstr.sub(base, p) == l }
			newl = @program.new_label(addrstr)
			rename_label l, newl
			l = newl
		end
		l
	end

	# sets the label for the specified address
	# returns nil if the address is not mapped
	def set_label_at(addr, name)
		addr = Expression[addr].reduce
		e, b = get_section_at(addr)
		if not e
		elsif not l = e.inv_export[e.ptr]
			l = @program.new_label(name)
			e.add_export l, e.ptr
			@prog_binding[l] = b + e.ptr
		elsif l != name
			l = rename_label l, @program.new_label(name)
		end
		l
	end

	# changes a label to another, updates referring instructions etc
	# returns the new label
	# the new label must be program-uniq (see @program.new_label)
	def rename_label(old, new)
		each_xref(normalize(old)) { |x|
			next if not di = @decoded[x.origin]
			@cpu.replace_instr_arg_immediate(di.instruction, old, new)
			di.comment.to_a.each { |c| c.gsub!(old, new) }
		}
		e, l = get_section_at(old)
		if e
			e.add_export new, e.export[old], true
		end
		@old_prog_binding[old] = @prog_binding[old]
		@prog_binding[new] = @prog_binding.delete(old)
		@addrs_todo.each { |at|
			case at[0]
			when old; at[0] = new
			when Expression; at[0] = at[0].bind(old => new)
			end
		}
		new
	end

	# decodes instructions from an entrypoint, (tries to) follows code flow
	def disassemble(*entrypoints)
		nil while disassemble_mainiter(entrypoints)
		self
	end

	attr_accessor :entrypoints

	# do one operation relevant to disassembling
	# returns nil once done
	def disassemble_mainiter(entrypoints=[])
		@entrypoints ||= []
		if @addrs_todo.empty? and entrypoints.empty?
			post_disassemble
			puts 'disassembly finished' if $VERBOSE
			return false
		elsif @addrs_todo.empty?
			ep = entrypoints.shift
			l = auto_label_at(normalize(ep), 'entrypoint')
			puts "start disassemble from #{l} (#{entrypoints.length})" if $VERBOSE and not entrypoints.empty?
			@entrypoints << l
			@addrs_todo << [ep]
		else
			disassemble_step
		end
		true
	end

	def post_disassemble
		@decoded.each_value { |di|
			next if not di.kind_of? DecodedInstruction
			next if not di.opcode or not di.opcode.props[:saveip]
			di.add_comment 'noreturn' if not di.block.to_subfuncret
		}
		@function.each { |addr, f|
			next if not di = @decoded[addr]
			@comment[addr] ||= []
			bd = f.backtrace_binding.reject { |k, v| Expression[k] == Expression[v] or Expression[v] == Expression::Unknown }
			unk = f.backtrace_binding.map { |k, v| k if v == Expression::Unknown }.compact
			bd[unk.map { |u| Expression[u].to_s }.sort.join(',')] = Expression::Unknown if not unk.empty?
			@comment[addr] |= ["function binding: " + bd.map { |k, v| "#{k} -> #{v}" }.sort.join(', ')]
			@comment[addr] |= ["function ends at " + f.return_address.map { |ra| Expression[ra] }.join(', ')] if f.return_address
		}
	end

	# disassembles one block from addrs_todo
	# adds next addresses to handle to addrs_todo
	# if @function[:default] exists, jumps to unknows locations are interpreted as to @function[:default]
	def disassemble_step
		@addrs_done ||= []
		return if not todo = @addrs_todo.pop or @addrs_done.include? todo
		@addrs_done << todo if todo[1]

		# from_sfret is true if from is the address of a function call that returns to addr
		addr, from, from_subfuncret = todo

		return if from == Expression::Unknown

		puts "disassemble_step #{Expression[addr]} #{Expression[from] if from} #{from_subfuncret}  (/#{@addrs_todo.length})" if $DEBUG

		addr = normalize(addr)

		if from and from_subfuncret and @decoded[from].kind_of? DecodedInstruction
			@decoded[from].block.each_to_normal { |subfunc|
				subfunc = normalize(subfunc)
				next if not f = @function[subfunc] or not f.need_finalize
				f.need_finalize = false
puts "  finalize subfunc #{Expression[subfunc]}" if debug_backtrace
				@cpu.backtrace_update_function_binding(self, subfunc, f, f.return_address)
				if not f.return_address
					detect_function_thunk(subfunc)
				end
			}
		end

		if di = @decoded[addr]
			if di.kind_of? DecodedInstruction
				split_block(di.block, di.address) if not di.block_head?	# this updates di.block
				di.block.add_from(from, from_subfuncret ? :subfuncret : :normal) if from and from != :default
				bf = di.block
			end
		elsif bf = @function[addr]
		elsif s = get_section_at(addr)
			block = InstructionBlock.new(normalize(addr), s[0])
			block.add_from(from, from_subfuncret ? :subfuncret : :normal) if from and from != :default
			disassemble_block(block)
		elsif from and c_parser and name = Expression[addr].reduce_rec and name.kind_of? ::String and
				s = c_parser.toplevel.symbol[name] and s.type.untypedef.kind_of? C::Function
			bf = @function[addr] = @cpu.decode_c_function_prototype(@c_parser, s)
		elsif from
			if bf = @function[:default]
				puts "using default function for #{Expression[addr]} from #{Expression[from]}" if $DEBUG
				if name = Expression[addr].reduce_rec and name.kind_of? ::String
					@function[addr] = @function[:default].dup
				else
					addr = :default
				end
				if @decoded[from]
					@decoded[from].block.add_to addr
				end
			else
				puts "not disassembling unknown address #{Expression[addr]} from #{Expression[from]}" if $DEBUG
			end
			if from != :default
				add_xref(addr, Xref.new(:x, from))
				add_xref(Expression::Unknown, Xref.new(:x, from))
			end
		else
			puts "not disassembling unknown address #{Expression[addr]}" if $VERBOSE
		end

		if bf and from and from != :default
			if bf.kind_of? DecodedFunction
				bff = bf.get_backtracked_for(self, addr, from)
			else
				bff = bf.backtracked_for
			end
		end
		bff.each { |btt|
			next if btt.address
			if @decoded[from].kind_of? DecodedInstruction and @decoded[from].opcode.props[:saveip] and not from_subfuncret and not @function[addr]
				backtrace_check_found(btt.expr, @decoded[addr], btt.origin, btt.type, btt.len, btt.maxdepth, btt.detached)
			end
			next if backtrace_check_funcret(btt, addr, from)
			backtrace(btt.expr, from,
				  :include_start => true, :from_subfuncret => from_subfuncret,
				  :origin => btt.origin, :orig_expr => btt.orig_expr, :type => btt.type,
				  :len => btt.len, :detached => btt.detached, :maxdepth => btt.maxdepth)
		} if bff
	end

	# splits an InstructionBlock, updates the blocks backtracked_for
	def split_block(block, address)
		return block if address == block.address
		new_b = block.split address
		todo = []	# array of [expr, off]
		new_b.backtracked_for.dup.each { |btt|
			backtrace(btt.expr, btt.address,
				  :include_start => !btt.exclude_instr, :from_subfuncret => btt.from_subfuncret,
				  :origin => btt.origin, :orig_expr => btt.orig_expr, :type => btt.type, :len => btt.len,
				  :snapshot_addr => block.address, :detached => btt.detached, :maxdepth => btt.maxdepth)
		}
		new_b
	end

	# disassembles a new instruction block at block.address (must be normalized)
	def disassemble_block(block)
		raise if not block.list.empty?
		di_addr = block.address
		delay_slot = nil

		# try not to run for too long
		# loop usage: break if the block continues to the following instruction, else return
		100.times {
			# check collision into a known block
			break if @decoded[di_addr]

			# decode instruction
			block.edata.ptr = di_addr - block.address + block.edata_ptr
			if not di = @cpu.decode_instruction(block.edata, di_addr)
				puts "unknown instruction to decode at #{Expression[di_addr]}" if $VERBOSE
				return
			end

			@decoded[di_addr] = di
			block.add_di di
			puts di if $DEBUG

			# check self-modifying code
			if @check_smc
				# uncomment to check for unaligned rewrites
				#(-7...di.bin_length).each { |off|
				waddr = di_addr		#di_addr + off
				each_xref(waddr, :w) { |x|
					#next if off + x.len < 0
					puts "W: disasm: self-modifying code at #{Expression[waddr]}" if $VERBOSE
					di.add_comment "overwritten by #{@decoded[x.origin] || Expression[x.origin]}"
					return
				}
				#}
			end

			# trace xrefs
			# PE SEH needs rw to be checked before x (for xrefs :w)
			@program.get_xrefs_rw(self, di).each { |type, ptr, len|
				backtrace(ptr, di_addr, :origin => di_addr, :type => type, :len => len).each { |xaddr|
					next if xaddr == Expression::Unknown
					# uncomment to check for unaligned rewrites
					if @check_smc and type == :w
						#len.times { |off|
						waddr = xaddr	#xaddr + off
						if wdi = @decoded[normalize(waddr)]
							puts "W: disasm: #{di} overwrites #{wdi}" if $VERBOSE
							wdi.add_comment "overwritten by #{di}"
						end
						#}
					end
				}
			}
			@program.get_xrefs_x(self, di).each { |expr|
				# di may be a return instruction, and the stack fixup may be in the delay slot (eg MIPS)
				# so we must wait until we have all the instrs in the instrblock before backtracking it
				# otherwise the update_func_binding return wrong results
				delay_slot ||= [di, @cpu.delay_slot(di)]
				delay_slot << expr if delay_slot[0] == di
			}

			di_addr = di.next_addr

			delay_slot ||= [di, @cpu.delay_slot(di)] if di.opcode.props[:stopexec] or not di_addr

			if delay_slot
				if delay_slot[1] == 0 or not di_addr
					di = delay_slot[0]
					delay_slot[2..-1].each { |expr| backtrace(expr, di.address, :origin => di.address, :type => :x) }
					return if di.opcode.props[:stopexec] or not di_addr
					break
				end
				delay_slot[1] -= 1
			end
		}

		if not callback_newaddr or di_addr = @callback_newaddr[di_addr, block.list.last.address]
			block.add_to di_addr
			@addrs_todo << [di_addr, block.list.last.address]
		end
		block
	end

	# checks if the function starting at funcaddr is an external function thunk (eg jmp [SomeExtFunc])
	# the argument must be the address of a decodedinstruction that is the first of a function,
	#  which must not have return_addresses
	# returns the new thunk name if it was changed
	def detect_function_thunk(funcaddr)
		# check thunk linearity (no conditionnal branch etc)
		addr = funcaddr
		count = 0
		while @decoded[addr].kind_of? DecodedInstruction
			count += 1
			return if count > 20
			b = @decoded[addr].block
			if b.to_subfuncret and not b.to_subfuncret.empty?
				return if b.to_subfuncret.length != 1
				addr = normalize(b.to_subfuncret.first)
				return if not b.to_normal or b.to_normal.length != 1
				# check that the subfunction is simple (eg get_eip)
				return if not sf = @function[normalize(b.to_normal.first)]
				return if not btb = sf.backtrace_binding or btb.length > 2 or btb.values.include? Expression::Unknown
			else
				return if not b.to_normal or b.to_normal.length != 1
				addr = normalize(b.to_normal.first)
			end
		end
		fname = Expression[addr].reduce_rec
		return if not fname.kind_of? ::String
		l = auto_label_at(funcaddr, 'sub')
		return if l[0, 4] != 'sub_'
		puts "found thunk for #{fname} at #{Expression[funcaddr]}" if $DEBUG
		rename_label(l, @program.new_label("thunk_#{fname}"))
	end


	# walks the backtrace tree from an address, passing along an object
	#
	# the steps are (1st = event, followed by hash keys)
	#
	# for each decoded instruction encountered:
	# :di       :di
	#
	# when backtracking to a block through a decodedfunction:
	# (yield for each of the block's subfunctions)
	# (the decodedinstruction responsible for the call will be yield next)
	# :func     :func, :funcaddr, :addr, :depth
	#
	# when jumping from one block to another (excluding :loop): # XXX include :loops ?
	# :up       :from, :to, :sfret
	#
	# when the backtrack has nothing to backtrack to (eg program entrypoint):
	# :end      :addr
	#
	# when the backtrack stops by taking too long to complete:
	# :maxdepth :addr
	#
	# when the backtrack stops for encountering the specified stop address:
	# :stopaddr :addr
	#
	# when rebacktracking a block already seen in the current branch:
	# (looptrace is an array of [obj, block end addr, from_subfuncret], from oldest to newest)
	# :loop     :looptrace
	#
	# when the address does not match a known instruction/function:
	# :unknown_addr :addr
	#
	# the block return value is used as follow for :di, :func, :up and :loop:
	# false => the backtrace stops for the branch
	# nil => the backtrace continues with the current object
	# anything else => the backtrace continues with this object
	#
	# method arguments:
	#  obj is the initial value of the object
	#  addr is the address where the backtrace starts
	#  include_start is a bool specifying if the backtrace should start at addr or just before
	#  from_subfuncret is a bool specifying if addr points to a decodedinstruction that calls a subfunction
	#  stopaddr is an [array of] address of instruction, the backtrace will stop just after executing it
	#  maxdepth is the maximum depth (in blocks) for each backtrace branch.
	#  (defaults to dasm.backtrace_maxblocks, which defaults do Dasm.backtrace_maxblocks)
	def backtrace_walk(obj, addr, include_start, from_subfuncret, stopaddr, maxdepth)
		start_addr = normalize(addr)
		stopaddr = [stopaddr] if stopaddr and not stopaddr.kind_of? ::Array

		# array of [obj, addr, from_subfuncret, loopdetect]
		# loopdetect is an array of [obj, addr, from_type] of each end of block encountered
		todo = []

		# array of [obj, blockaddr]
		# avoids rewalking the same value
		done = []

		# updates todo with the addresses to backtrace next
		walk_up = proc { |w_obj, w_addr, w_loopdetect|
			if w_loopdetect.length > maxdepth
				yield :maxdepth, w_obj, :addr => w_addr, :loopdetect => w_loopdetect
			elsif stopaddr and stopaddr.include?(w_addr)
				yield :stopaddr, w_obj, :addr => w_addr, :loopdetect => w_loopdetect
			elsif w_di = @decoded[w_addr] and w_di != w_di.block.list.first and w_di.address != w_di.block.address
				prevdi = w_di.block.list[w_di.block.list.index(w_di)-1]
				todo << [w_obj, prevdi.address, :normal, w_loopdetect]
			elsif w_di
				next if done.include? [w_obj, w_addr]
				done << [w_obj, w_addr]
				hadsomething = false
				w_di.block.each_from { |f_addr, f_type|
					next if f_type == :indirect
					hadsomething = true
					if l = w_loopdetect.find { |l_obj, l_addr, l_type| l_addr == f_addr and l_type == f_type }
						f_obj = yield(:loop, w_obj, :looptrace => w_loopdetect[w_loopdetect.index(l)..-1], :loopdetect => w_loopdetect)
						if f_obj and f_obj != w_obj	# should avoid infinite loops
							f_loopdetect = w_loopdetect[0...w_loopdetect.index(l)]
						end
					else
						f_obj = yield(:up, w_obj, :from => w_addr, :to => f_addr, :sfret => f_type, :loopdetect => w_loopdetect)
					end
					next if f_obj == false
					f_obj ||= w_obj
					f_loopdetect ||= w_loopdetect
					todo << [f_obj, f_addr, f_type, f_loopdetect + [[f_obj, f_addr, f_type]] ]
				}
				yield :end, w_obj, :addr => w_addr, :loopdetect => w_loopdetect if not hadsomething
			elsif @function[w_addr] and w_addr != :default and w_addr != Expression::Unknown
				next if done.include? [w_obj, w_addr]
				oldlen = todo.length
				each_xref(w_addr, :x) { |x|
					if l = w_loopdetect.find { |l_obj, l_addr, l_type| l_addr == w_addr }
						f_obj = yield(:loop, w_obj, :looptrace => w_loopdetect[w_loopdetect.index(l)..-1], :loopdetect => w_loopdetect)
						if f_obj and f_obj != w_obj
							f_loopdetect = w_loopdetect[0...w_loopdetect.index(l)]
						end
					else
						f_obj = yield(:up, w_obj, :from => w_addr, :to => x.origin, :sfret => :normal, :loopdetect => w_loopdetect)
					end
					next if f_obj == false
					f_obj ||= w_obj
					f_loopdetect ||= w_loopdetect
					todo << [f_obj, x.origin, :normal, f_loopdetect + [[f_obj, x.origin, :normal]] ]
				}
				yield :end, w_obj, :addr => w_addr, :loopdetect => w_loopdetect if todo.length == oldlen
			else
				yield :unknown_addr, w_obj, :addr => w_addr, :loopdetect => w_loopdetect
			end
		}

		if include_start
			todo << [obj, start_addr, from_subfuncret ? :subfuncret : :normal, []]
		else
			walk_up[obj, start_addr, []]
		end

		while not todo.empty?
			obj, addr, type, loopdetect = todo.pop
			di = @decoded[addr]
			if type == :subfuncret
				di.block.each_to_normal { |sf|
					next if not f = @function[normalize(sf)]
					s_obj = yield(:func, obj, :func => f, :funcaddr => sf, :addr => addr, :loopdetect => loopdetect)
					next if s_obj == false
					s_obj ||= obj
					if l = loopdetect.find { |l_obj, l_addr, l_type| addr == l_addr and l_type == :normal }
						l_obj = yield(:loop, s_obj, :looptrace => loopdetect[loopdetect.index(l)..-1], :loopdetect => loopdetect)
						if l_obj and l_obj != s_obj
							s_loopdetect = loopdetect[0...loopdetect.index(l)]
						end
						next if l_obj == false
						s_obj = l_obj if l_obj
					end
					s_loopdetect ||= loopdetect
					todo << [s_obj, addr, :normal, s_loopdetect + [[s_obj, addr, :normal]] ]
				}
			elsif di
				# XXX should interpolate index if di is not in block.list, but what if the addresses are not Comparable ?
				di.block.list[0..(di.block.list.index(di) || -1)].reverse_each { |di|
					if stopaddr and ea = di.next_addr and stopaddr.include?(ea)
						yield :stopaddr, obj, :addr => ea, :loopdetect => loopdetect
						break
					end
					ex_obj = obj
					obj = yield(:di, obj, :di => di, :loopdetect => loopdetect)
					break if obj == false
					obj ||= ex_obj
				}
				walk_up[obj, di.block.address, loopdetect] if obj
			elsif @function[addr] and addr != :default and addr != Expression::Unknown
				ex_obj = obj
				obj = yield(:func, obj, :func => @function[addr], :funcaddr => addr, :addr => addr, :loopdetect => loopdetect)
				next if obj == false
				obj ||= ex_obj
				walk_up[obj, addr, loopdetect]
			else
				yield :unknown_addr, obj, :addr => addr, :loopdetect => loopdetect
			end
		end
	end

	# holds a backtrace result until a snapshot_addr is encountered
	class StoppedExpr
		attr_accessor :exprs
		def initialize(e) @exprs = e end
	end


	attr_accessor :debug_backtrace

	# backtraces the value of an expression from start_addr
	# updates blocks backtracked_for if type is set
	# uses backtrace_walk
	# all values returned are from backtrace_check_found (which may generate xrefs, labels, addrs to dasm)
	# options:
	#  :include_start => start backtracking including start_addr
	#  :from_subfuncret => 
	#  :origin => origin to set for xrefs when resolution is successful
	#  :orig_expr => initial expression
	#  :type => xref type (:r, :w, :x, :addr)  when :x, the results are added to #addrs_todo
	#  :len => xref len (for :r/:w)
	#  :snapshot_addr => addr (or array of) where the backtracker should stop
	#   if a snapshot_addr is given, values found are ignored if continuing the backtrace does not get to it (eg maxdepth/unk_addr/end)
	#  :maxdepth => maximum number of blocks to backtrace
	#  :detached => true if backtracking type :x and the result should not have from = origin set in @addrs_todo
	#  :max_complexity{_data} => maximum complexity of the expression before aborting its backtrace
	#  :log => Array, will be updated with the backtrace evolution
	# XXX origin/type/len/detached -> BacktraceTrace ?
	def backtrace(expr, start_addr, nargs={})
		include_start   = nargs.delete :include_start
		from_subfuncret = nargs.delete :from_subfuncret
		origin          = nargs.delete :origin
		origexpr        = nargs.delete :orig_expr
		type            = nargs.delete :type
		len             = nargs.delete :len
		snapshot_addr   = nargs.delete :snapshot_addr
		maxdepth        = nargs.delete(:maxdepth) || @backtrace_maxblocks
		detached        = nargs.delete :detached
		max_complexity  = nargs.delete(:max_complexity) || 40
		max_complexity_data = nargs.delete(:max_complexity) || 8
		bt_log          = nargs.delete :log	# array to receive the ongoing backtrace info
		raise ArgumentError, "invalid argument to backtrace #{nargs.keys.inspect}" if not nargs.empty?

		expr = Expression[expr]

		origexpr = expr if origin == start_addr

		start_addr = normalize(start_addr)
		di = @decoded[start_addr]

		if not snapshot_addr and @cpu.backtrace_is_stack_address(expr)
puts "  not backtracking stack address #{expr}" if debug_backtrace
			return []
		end
		
		if type == :r or type == :w
			max_complexity = max_complexity_data
			maxdepth = @backtrace_maxblocks_data if backtrace_maxblocks_data and maxdepth > @backtrace_maxblocks_data
		end

		if result = backtrace_check_found(expr, di, origin, type, len, maxdepth, detached)
			# no need to update backtrace_for
			return result
		elsif maxdepth <= 0
			return [Expression::Unknown]
		end
		
		# create initial backtracked_for
		if type and origin == start_addr and di
			btt = BacktraceTrace.new(expr, origin, origexpr, type, len, maxdepth-1)
			btt.address = di.address
			btt.exclude_instr = true if not include_start
			btt.from_subfuncret = true if from_subfuncret and include_start
			btt.detached = true if detached
			di.block.backtracked_for |= [btt]
		end

		# list of Expression/Integer
		result = []

puts "backtracking #{type} #{expr} from #{di || Expression[start_addr || 0]} for #{@decoded[origin]}" if debug_backtrace or $DEBUG
		bt_log << [:start, expr, start_addr] if bt_log
		backtrace_walk(expr, start_addr, include_start, from_subfuncret, snapshot_addr, maxdepth) { |ev, expr, h|
			case ev
			when :unknown_addr, :maxdepth
puts "  backtrace end #{ev} #{expr}" if debug_backtrace
				result |= [expr] if not snapshot_addr
				@addrs_todo << [expr, (detached ? nil : origin)] if not snapshot_addr and type == :x and origin
			when :end
				if not expr.kind_of? StoppedExpr
					oldexpr = expr
					expr = backtrace_emu_blockup(h[:addr], expr)
puts "  backtrace up #{Expression[h[:addr]]}  #{oldexpr}#{" => #{expr}" if expr != oldexpr}" if debug_backtrace
					bt_log << [:up, expr, oldexpr, h[:addr],  :end] if bt_log and expr != oldexpr
					if expr != oldexpr and not snapshot_addr and vals = backtrace_check_found(expr,
							nil, origin, type, len, maxdepth-h[:loopdetect].length, detached)
						result |= vals
						next
					end
				end
puts "  backtrace end #{ev} #{expr}" if debug_backtrace
				if not snapshot_addr
					result |= [expr]

					btt = BacktraceTrace.new(expr, origin, origexpr, type, len, maxdepth-h[:loopdetect].length-1)
					btt.detached = true if detached
					@decoded[h[:addr]].block.backtracked_for |= [btt] if @decoded[h[:addr]]
					@function[h[:addr]].backtracked_for |= [btt] if @function[h[:addr]] and h[:addr] != :default
					@addrs_todo << [expr, (detached ? nil : origin)] if type == :x and origin
				end
			when :stopaddr
				if not expr.kind_of? StoppedExpr
					oldexpr = expr
					expr = backtrace_emu_blockup(h[:addr], expr)
puts "  backtrace up #{Expression[h[:addr]]}  #{oldexpr}#{" => #{expr}" if expr != oldexpr}" if debug_backtrace
					bt_log << [:up, expr, oldexpr, h[:addr], :end] if bt_log and expr != oldexpr
				end
puts "  backtrace end #{ev} #{expr}" if debug_backtrace
				result |= ((expr.kind_of?(StoppedExpr)) ? expr.exprs : [expr])
			when :loop
				next false if expr.kind_of? StoppedExpr
				t = h[:looptrace]
				oldexpr = t[0][0]
				next false if expr == oldexpr		# unmodifying loop
puts "  bt loop at #{Expression[t[0][1]]}: #{oldexpr} => #{expr} (#{t.map { |z| Expression[z[1]] }.join(' <- ')})" if debug_backtrace
				false
			when :up
				next expr if expr.kind_of? StoppedExpr
				oldexpr = expr
				expr = backtrace_emu_blockup(h[:from], expr)
puts "  backtrace up #{Expression[h[:from]]}->#{Expression[h[:to]]}  #{oldexpr}#{" => #{expr}" if expr != oldexpr}" if debug_backtrace
				bt_log << [:up, expr, oldexpr, h[:from], h[:to]] if bt_log
				if expr != oldexpr and vals = backtrace_check_found(expr,
						nil, origin, type, len, maxdepth-h[:loopdetect].length, detached)
					if snapshot_addr
						expr = StoppedExpr.new vals
						next expr
					else
						result |= vals
						next false
					end
				end

				if origin and type
					# update backtracked_for
					update_btf = proc { |btf, new_btt|
						# returns true if btf was modified
						if i = btf.index(new_btt)
							btf[i] = new_btt if btf[i].maxdepth < new_btt.maxdepth
						else
							btf << new_btt
						end
					}

					btt = BacktraceTrace.new(expr, origin, origexpr, type, len, maxdepth-h[:loopdetect].length-1)
					btt.detached = true if detached
					if x = @decoded[h[:from]] and x.kind_of? DecodedInstruction
						if not update_btf[x.block.backtracked_for, btt]
puts "   already backtraced" if debug_backtrace
							next false
						end
					end
					if x = @function[h[:from]] and h[:from] != :default
						update_btf[x.backtracked_for, btt]
					end
					if x = @decoded[h[:to]] and x.kind_of? DecodedInstruction
						btt = btt.dup
						btt.address = x.address
						btt.from_subfuncret = true if h[:sfret] == :subfuncret
						if backtrace_check_funcret(btt, h[:from], h[:to])
puts "   function returns to caller" if debug_backtrace
							next false 
						end
						update_btf[x.block.backtracked_for, btt]
					end
				end
				expr
			when :di, :func
				next if expr.kind_of? StoppedExpr
				if not snapshot_addr and @cpu.backtrace_is_stack_address(expr)
puts "  not backtracking stack address #{expr}" if debug_backtrace
					next false
				end

oldexpr = expr
				case ev
				when :di; expr = backtrace_emu_instr(h[:di], expr)
				when :func; expr = backtrace_emu_subfunc(h[:func], h[:funcaddr], h[:addr], expr, origin, maxdepth-h[:loopdetect].length)
				if snapshot_addr and snapshot_addr == h[:funcaddr]
puts "  backtrace: recursive function #{Expression[h[:funcaddr]]}" if debug_backtrace
					next false
				end
				end
puts "  backtrace #{h[:di] || Expression[h[:funcaddr]]}  #{oldexpr} => #{expr}" if debug_backtrace and expr != oldexpr
				if ev == :di
					bt_log << [ev, expr, oldexpr, h[:di]] if bt_log and expr != oldexpr
				else
					bt_log << [ev, expr, oldexpr, h[:addr], h[:funcaddr]] if bt_log and expr != oldexpr
				end
				if vals = backtrace_check_found(expr, h[:di], origin, type, len, maxdepth-h[:loopdetect].length, detached)
					if snapshot_addr
						expr = StoppedExpr.new vals
					else
						result |= vals
						next false
					end
				elsif expr.complexity > max_complexity
puts "  backtrace aborting, expr too complex" if debug_backtrace
					next false
				end
				expr
			else raise ev.inspect
			end
		}

puts '  backtrace result: ' + result.map { |r| Expression[r] }.join(', ') if debug_backtrace

		result
	end

	# checks if the BacktraceTrace is a call to a known subfunction
	# returns true and updates self.addrs_todo
	def backtrace_check_funcret(btt, funcaddr, instraddr)
		if di = @decoded[instraddr] and @function[funcaddr] and btt.type == :x and
				not btt.from_subfuncret and
				@cpu.backtrace_is_function_return(btt.expr) and
				retaddr = backtrace_emu_instr(di, btt.expr) and
				not need_backtrace(retaddr)
puts "  backtrace addrs_todo << #{Expression[retaddr]} from #{di} (funcret)" if debug_backtrace
			di.block.add_to_subfuncret normalize(retaddr)
			if @function[funcaddr].need_finalize
				# the function is not fully disassembled: arrange for the retaddr to be
				#  disassembled only after the subfunction is finished
				# for that we walk the code from the call, mark each block start, and insert the sfret
				#  just before the 1st function block address in @addrs_todo (which is pop()ed by dasm_step)
				faddrlist = []
				todo = []
				di.block.each_to_normal { |t| todo << normalize(t) }
				while a = todo.pop
					next if faddrlist.include? a or not get_section_at(a)
					faddrlist << a
					if @decoded[a].kind_of? DecodedInstruction
						@decoded[a].block.each_to_samefunc(self) { |t| todo << normalize(t) }
					end
				end

				idx = @addrs_todo.index(@addrs_todo.find { |r, i, sfr| faddrlist.include? normalize(r) }) || -1
				@addrs_todo.insert(idx, [retaddr, instraddr, true])
			else
				@addrs_todo << [retaddr, instraddr, true]
			end
			true
		end
	end

	# applies one decodedinstruction to an expression
	def backtrace_emu_instr(di, expr)
		@cpu.backtrace_emu(di, expr)
	end

	# applies one subfunction to an expression
	def backtrace_emu_subfunc(func, funcaddr, calladdr, expr, origin, maxdepth)
		bind = func.get_backtrace_binding(self, funcaddr, calladdr, expr, origin, maxdepth)
		Expression[expr.bind(bind).reduce]
	end

	# applies a location binding
	def backtrace_emu_blockup(addr, expr)
		(ab = @address_binding[addr]) ? Expression[expr.bind(ab).reduce] : expr
	end

	# static resolution of indirections
	def resolve(expr)
		binding = Expression[expr].expr_indirections.inject(@prog_binding.merge(@old_prog_binding)) { |binding, ind|
			e, b = get_section_at(resolve(ind.target))
			return expr if not e
			binding.merge ind => Expression[ e.decode_imm("u#{8*ind.len}".to_sym, @cpu.endianness) ]
		}
		Expression[expr].bind(binding).reduce
	end

	# returns true if the expression needs more backtrace
	# it checks for the presence of a symbol (not :unknown), which means it depends on some register value
	def need_backtrace(expr)
		return if expr.kind_of? ::Integer
		not (expr.externals.grep(::Symbol) - [:unknown]).empty?
	end

	# returns an array of expressions, or nil if expr needs more backtrace
	# it needs more backtrace if expr.externals include a Symbol != :unknown (symbol == register value)
	# if it need no more backtrace, expr's indirections are recursively resolved
	# xrefs are created, and di args are updated (immediate => label)
	# if type is :x, addrs_todo is updated, and if di starts a block, expr is checked to see if it may be a subfunction return value
	#
	# expr indirection are solved by first finding the value of the pointer, and then rebacktracking for write-type access
	# detached is true if type is :x and from should not be set in addrs_todo (indirect call flow, eg external function callback)
	# if the backtrace ends pre entrypoint, returns the value encoded in the raw binary
	# XXX global variable (modified by another function), exported data, multithreaded app..
	# TODO handle memory aliasing (mov ebx, eax ; write [ebx] ; read [eax])
	# TODO trace expr evolution through backtrace, to modify immediates to an expr involving label names
	# TODO mov [ptr], imm ; <...> ; jmp [ptr] => rename imm as loc_XX
	#  eg. mov eax, 42 ; add eax, 4 ; jmp eax  =>  mov eax, some_label-4
	def backtrace_check_found(expr, di, origin, type, len, maxdepth, detached)
		# only entrypoints or block starts called by a :saveip are checked for being a function
		# want to execute [esp] from a block start
		if type == :x and di and di == di.block.list.first and @cpu.backtrace_is_function_return(expr) and (
			# which is an entrypoint..
			(not di.block.from_normal and not di.block.from_subfuncret) or
			# ..or called from a saveip
			(bool = false ; di.block.each_from_normal { |fn| bool = true if @decoded[fn] and @decoded[fn].opcode.props[:saveip] } ; bool))

			# now we can mark the current address a function start
			# the actual return address will be found later (we tell the caller to continue the backtrace)
			addr = di.address
			l = auto_label_at(addr, 'sub', 'loc', 'xref')
			if not f = @function[addr]
				f = @function[addr] = DecodedFunction.new
				puts "found new function #{l} at #{Expression[addr]}" if $VERBOSE
			end
			f.need_finalize = true

			if @decoded[origin]
				f.return_address ||= []
				f.return_address |= [origin]
				@decoded[origin].add_comment "endsub #{l}"
				# TODO add_xref (to update the comment on rename_label)
			end

			f.backtracked_for |= @decoded[addr].block.backtracked_for.find_all { |btt| not btt.address }
			@cpu.backtrace_update_function_binding(self, addr, f, [origin])
puts "backtrace function binding for #{l}:", f.backtrace_binding.map { |k, v| " #{k} -> #{v}" }.sort if $DEBUG
		end

		return if need_backtrace(expr)

puts "backtrace #{type} found #{expr} from #{di} orig #{@decoded[origin] || Expression[origin] if origin}" if debug_backtrace
		result = backtrace_value(expr, maxdepth)

		# create xrefs/labels
		result.each { |e|
			backtrace_found_result(e, di, type, origin, len, detached)
		} if type and origin

		result
	end

	# returns an array of expressions with Indirections resolved (recursive with backtrace_indirection)
	def backtrace_value(expr, maxdepth)
		# array of expression with all indirections resolved
		result = [Expression[expr.reduce]]

		# solve each indirection sequentially, clone expr for each value (aka cross-product)
		result.first.expr_indirections.uniq.each { |i|
			next_result = []
			backtrace_indirection(i, maxdepth).each { |rr|
				next_result |= result.map { |e| Expression[e.bind(i => rr).reduce] }
			}
			result = next_result
		}

		result.uniq
	end

	# returns the array of values pointed by the indirection at its invocation (ind.origin)
	# first resolves the pointer using backtrace_value, if it does not point in edata keep the original pointer
	# then backtraces from ind.origin until it finds an :w xref origin
	# if no :w access is found, returns the value encoded in the raw section data
	# TODO handle unaligned (partial?) writes
	def backtrace_indirection(ind, maxdepth)
		if not ind.origin
			puts "backtrace_ind: no origin for #{ind}" if $VERBOSE
			return [ind]
		end

		ret = []

		decode_imm = proc { |addr, len|
			edata, foo = get_section_at(addr)
			if edata
				Expression[ edata.decode_imm("u#{8*len}".to_sym, @cpu.endianness) ]
			else
				Expression::Unknown
			end
		}

		# resolve pointers (they may include Indirections)
		backtrace_value(ind.target, maxdepth).each { |ptr|
			# find write xrefs to the ptr
			refs = []
			each_xref(ptr, :w) { |x|
				# XXX should be rebacktracked on new xref
				next if not @decoded[x.origin]
				refs |= [x.origin]
			} if ptr != Expression::Unknown

			if refs.empty?
				if get_section_at(ptr)
					# static data, newer written : return encoded value
					ret |= [decode_imm[ptr, ind.len]]
					next
				else
					# unknown pointer : backtrace the indirection, hope it solves itself
					initval = ind
				end
			else
				# wait until we find a write xref, then backtrace the written value
				initval = true
			end

			# wait until we arrive at an xref'ing instruction, then backtrace the written value
			backtrace_walk(initval, ind.origin, true, false, nil, maxdepth-1) { |ev, expr, h|
				case ev
				when :unknown_addr, :maxdepth, :stopaddr
puts "   backtrace_indirection for #{ind.target} failed: #{ev}" if debug_backtrace
					ret |= [Expression::Unknown]
				when :end
					if not refs.empty? and (expr == true or not need_backtrace(expr))
						if expr == true
							# found a path avoiding the :w xrefs, read the encoded initial value
							ret |= [decode_imm[ptr, ind.len]]
						else
							bd = expr.expr_indirections.inject({}) { |h, i| h.update i => decode_imm[i.target, i.len] }
							ret |= [Expression[expr.bind(bd).reduce]]
						end
					else
						# unknown pointer, backtrace did not resolve...
						ret |= [Expression::Unknown]
					end
				when :di
					di = h[:di]
					if expr == true
						next true if not refs.include? di.address
						# find the expression to backtrace: assume this is the :w xref from this di
						writes = @program.get_xrefs_rw(self, di)
						writes = writes.find_all { |x_type, x_ptr, x_len| x_type == :w and x_len == ind.len }
						if writes.length != 1
							puts "backtrace_ind: incompatible xrefs to #{ptr} from #{di}" if $DEBUG
							ret |= [Expression::Unknown]
							next false
						end
						expr = Indirection.new(writes[0][1], ind.len, di.address)
					end
					expr = backtrace_emu_instr(di, expr)
					# may have new indirections... recall bt_value ?
					#if not need_backtrace(expr)
					if expr.expr_externals.all? { |e| @prog_binding[e] or @function[normalize(e)] } and expr.expr_indirections.empty?
						ret |= backtrace_value(expr, maxdepth-1-h[:loopdetect].length)
						false
					else
						expr
					end
				when :func
					next true if expr == true	# XXX
					expr = backtrace_emu_subfunc(h[:func], h[:funcaddr], h[:addr], expr, ind.origin, maxdepth-h[:loopdetect].length)
					#if not need_backtrace(expr)
					if expr.expr_externals.all? { |e| @prog_binding[e] or @function[normalize(e)] } and expr.expr_indirections.empty?
						ret |= backtrace_value(expr, maxdepth-1-h[:loopdetect].length)
						false
					else
						expr
					end
				end
			}
		}

		ret
	end

	# creates xrefs, updates addrs_todo, updates instr args
	def backtrace_found_result(expr, di, type, origin, len, detached)
		n = normalize(expr)
		add_xref(n, Xref.new(type, origin, len)) if origin != :default and origin != Expression::Unknown
		unk = true if n == Expression::Unknown

		add_xref(n, Xref.new(:addr, di.address)) if di and di.address != origin and not unk
		base = { nil => 'loc', 1 => 'byte', 2 => 'word', 4 => 'dword' }[len] || 'xref'
		base = 'sub' if @function[n]
		n = Expression[auto_label_at(n, base, 'xref') || n]

		# update instr args
		# TODO trace expression evolution to allow handling of
		#  mov eax, 28 ; add eax, 4 ; jmp eax
		#  => mov eax, (loc_xx-4)
		if di and not unk # and di.address == origin
			@cpu.replace_instr_arg_immediate(di.instruction, expr, n)
		end
		if @decoded[origin] and not unk
			 @cpu.backtrace_found_result(self, @decoded[origin], expr, type, len)
		end

		# add comment
		if type and @decoded[origin] # and not @decoded[origin].instruction.args.include? n
			@decoded[origin].add_comment "#{type}#{len}:#{n}"
		end

		# check if target is a string
		if di and type == :r and (len == 1 or len == 2) and s = get_section_at(n)
			l = s[0].inv_export[s[0].ptr]
			case len
			when 1; str = s[0].read(32).unpack('C*')
			when 2; str = s[0].read(64).unpack('v*')
			end
			str = str.inject('') { |str, c|
				case c
				when 0x20..0x7e, ?\n, ?\r, ?\t; str << c
				else break str
				end
			}
			if str.length >= 4
				di.add_comment "#{'L' if len == 2}#{str.inspect}"
				str = 'a_' + str.downcase.delete('^a-z0-9')[0, 12]
				if str.length >= 8 and l[0, 5] == 'byte_'
					rename_label(l, @program.new_label(str))
				end
			end
		end

		# XXX all this should be done in  backtrace() { <here> }
		if type == :x and origin and (not callback_newaddr or n = @callback_newaddr[n, origin])
			if detached
				o = @decoded[origin] ? origin : di ? di.address : nil	# lib function callback have origin == libfuncname, so we must find a block somewhere else
				origin = nil
				@decoded[o].block.add_to_indirect(normalize(n)) if @decoded[o] and not unk
			else
				@decoded[origin].block.add_to_normal(normalize(n)) if @decoded[origin] and not unk
			end
			@addrs_todo << [n, origin]
		end
	end


	def to_s
		a = ''
		dump { |l| a << l << "\n" }
		a
	end

	# dumps the source, optionnally including data
	# yields (defaults puts) each line
	def dump(dump_data=true, &b)
		b ||= proc { |l| puts l }
		@sections.sort.each { |addr, edata|
			blockoffs = @decoded.values.map { |di| Expression[di.block.address, :-, addr].reduce if di.kind_of? DecodedInstruction and di.block_head? }.grep(::Integer).sort.reject { |o| o < 0 or o >= edata.length }
			b[@program.dump_section_header(addr, edata)]
			if not dump_data and edata.length > 16*1024 and blockoffs.empty?
				b["// [#{edata.length} data bytes]"]
				next
			end
			unk_off = 0
			# blocks.sort_by { |b| b.addr }.each { |b|
			edata.length.times { |i|
				if di = @decoded[addr+i] and di.kind_of? DecodedInstruction and di.block_head?
					if unk_off != di.block.edata_ptr
						b["\n// ------ overlap (#{unk_off-di.block.edata_ptr}) ------"]
					elsif di.block.from_normal.kind_of? ::Array
						b["\n"]
					end
					dump_block(di.block, &b)
					unk_off = i + di.block.bin_length
				elsif i >= unk_off
					next_off = blockoffs.find { |bo| bo > i } || edata.length
					if dump_data or next_off - i < 16
						unk_off = dump_data(addr + unk_off, edata, unk_off, &b)
					else
						b["// [#{next_off - i} data bytes]"]
						unk_off = next_off
					end
				end
			}
		}
	end

	# dumps a block of decoded instructions
	def dump_block(block, &b)
		b ||= proc { |l| puts l }
		dump_block_header(block, &b)
		block.list.each { |di| b[di.show] }
	end

	# shows the xrefs/labels at block start
	def dump_block_header(block, &b)
		b ||= proc { |l| puts l }
		xr = []
		each_xref(block.address) { |x|
			case x.type
			when :x; xr << Expression[x.origin]
			when :r, :w; xr << "#{x.type}#{x.len}:#{Expression[x.origin]}"
			end
		}
		if not xr.empty?
			b["\n// Xrefs: #{xr[0, 8].join(' ')}#{' ...' if xr.length > 8}"]
		end
		if @prog_binding.index(block.address)
			b["\n"] if xr.empty?
			@prog_binding.keys.sort.each { |name| b["#{name}:"] if @prog_binding[name] == block.address }
		end
		if c = @comment[block.address]
			c.each { |l| b["// #{l}"] }
		end
	end

	# dumps data/labels, honours @xrefs.len if exists
	# dumps one line only
	# stops on end of edata/@decoded/@xref
	# returns the next offset to display
	# TODO array-style data access
	def dump_data(addr, edata, off, &b)
		b ||= proc { |l| puts l }
		if l = @prog_binding.index(addr)
			l = (l + ' ').ljust(16)
		else l = ''
		end
		elemlen = 1	# size of each element we dump (db by default)
		dumplen = -off % 16	# number of octets to dump
		dumplen = 16 if dumplen == 0
		cmt = []
		each_xref(addr) { |x|
			dumplen = elemlen = x.len if x.len == 2 or x.len == 4
			cmt << " #{x.type}#{x.len}:#{Expression[x.origin]}"
		}
		cmt = " ; @#{Expression[addr]}" + cmt.sort[0, 6].join
		if r = edata.reloc[off]
			dumplen = elemlen = r.type.to_s[1..-1].to_i/8
		end
		dataspec = { 1 => 'db ', 2 => 'dw ', 4 => 'dd ' }[elemlen]
		l << dataspec

		# dup(?)
		if off >= edata.data.length
			dups = edata.virtsize - off
			tmp = nil
			if @prog_binding.values.find { |a|
				tmp = Expression[a, :-, addr].reduce
				tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
			}
				dups = tmp
			end
			if @xrefs.keys.find { |a|
				tmp = Expression[a, :-, addr].reduce
				tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
			}
				dups = tmp
			end
			dups /= elemlen
			dups = 1 if dups < 1
			b[l + "#{dups} dup(?)"]
			return off + dups*elemlen
		end

		vals = []
		edata.ptr = off
		dups = dumplen/elemlen
		while edata.ptr < edata.data.length
			if vals.length > dups and vals.uniq.length > 1
				vals.pop
				addr = Expression[addr, :-, elemlen].reduce
				edata.ptr -= elemlen
				break
			end
			break if vals.length == dups and vals.uniq.length > 1
			vals << edata.decode_imm("u#{elemlen*8}".to_sym, @cpu.endianness)
			addr += elemlen
			if i = (1-elemlen..0).find { |i|
				t = addr + i
				@xrefs[t] or @decoded[t] or edata.reloc[edata.ptr+i] or edata.inv_export[edata.ptr+i]
			}
				edata.ptr += i
				addr += i
				break
			end
			break if edata.reloc[edata.ptr-elemlen]
		end

		# line of repeated value => dup()
		if vals.length > 8 and vals.uniq.length == 1
			b[(l << "#{vals.length} dup(#{Expression[vals.first]})").ljust(48) << cmt]
			return edata.ptr
		end

		# recognize strings
		vals = vals.inject([]) { |vals, value|
			if (elemlen == 1 or elemlen == 2)
				case value
				when 0x20..0x7e, 0x0a, 0x0d
					if vals.last.kind_of? ::String; vals.last << value ; vals
					else vals << value.chr
					end
				else vals << value
				end
			else vals << value
			end
		}

		vals.map! { |value|
			if value.kind_of? ::String
				if value.length > 2 # or value == vals.first or value == vals.last # if there is no xref, don't care
					value.inspect
				else
					value.unpack('C*').map { |c| Expression[c] }
				end
			else
				Expression[value]
			end
		}
		vals.flatten!

		b[(l << vals.join(', ')).ljust(48) << cmt]

		edata.ptr
	end
end
end
