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
	# our offset (in bytes) from the start of the block
	attr_accessor :block_offset
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

	def address
		Expression[@block.address, :+, @block_offset].reduce
	end

	def to_s
		"#{Expression[address]} #{instruction}"
	end

	def add_comment(c)
		@comment ||= []
		@comment |= [c]
	end
end

# defines a class method attr_accessor_list to declare an attribute that may have multiple values
module AccessorList
	# defines an attribute that may be a value or an array, along with its accessors
	# used to optimize ruby's memory usage with many objects that have mostly single-value attributes
	# the values must not be arrays !
	def attr_accessor_list(*a)
		a.each { |a|
			# XXX no way to yield from a define_method block...
			class_eval <<EOS
	attr_accessor :#{a}

	def each_#{a}
		case #{a}
		when nil
		when ::Array: @#{a}.each { |b| yield b }
		else yield @#{a}
		end
	end

	def add_#{a}(b)
		case #{a}
		when nil: @#{a} = b
		when b
		when ::Array: @#{a} |= [b]
		else @#{a} = [@#{a}, b]
		end
	end
EOS
		}
	end
end

# holds information on a backtracked expression near begin and end of instruction blocks (#backtracked_for)
class BacktraceTrace
	# offset of the instruction in the block from which rebacktrace should start (use with from_subfuncret bool)
	# exclude_instr is a bool saying if the backtrace should start at block_offset or at the preceding instruction
	# optional: if absent, expr is to be rebacktracked when a new codepath arrives at the beginning of the block
	attr_accessor :block_offset, :from_subfuncret, :exclude_instr
	# address of the instruction that initiated the backtrace
	attr_accessor :origin
	# the Expression to backtrace at this point
	attr_accessor :expr
	# length of r/w xref (in bytes)
	attr_accessor :len
	# :r/:w/:x
	attr_accessor :type
	# bool: true if this maps to a :x that should not have a from when resolved
	attr_accessor :detached
	# maxdepth at the point of the object creation
	attr_accessor :maxdepth

	def initialize(expr, origin, type, len=nil, maxdepth=nil)
		@expr, @origin, @type = expr, origin, type
		@len = len if len
		@maxdepth = maxdepth if maxdepth
	end

	def hash ; [origin, expr].hash ; end
	def eql?(o)
		o.class == self.class and
		[block_offset, from_subfuncret, origin, expr, len, type] ==
		 [o.block_offset, o.from_subfuncret, o.origin, o.expr, o.len, o.type]
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
	extend AccessorList

	# address of the first instruction
	attr_accessor :address
	# pointer to raw data
	attr_accessor :edata, :edata_ptr
	# list of DecodedInstructions
	attr_accessor :list
	# address of instructions giving control directly to us
	# includes addr of normal instruction when call flow continues to us past the end of the preceding block
	# does not include addresses of subfunction return instructions
	attr_accessor_list :from_normal
	# address of instructions called/jumped to
	# does not include addresses of subfunctions called
	attr_accessor_list :to_normal
	# address of an instruction that calls a subfunction which returns to us
	attr_accessor_list :from_subfuncret
	# address of instruction executed after a called subfunction returns
	attr_accessor_list :to_subfuncret
	# addresses of subfunctions called
	attr_accessor_list :subfunction
	# array of BacktraceTrace
	# when a new code path comes to us, it should be backtracked for the values of :r/:w/:x using btt with no block_offset
	# for internal use only (block splitting): btt with a block_offset
	attr_accessor :backtracked_for

	def initialize(address, edata, edata_ptr=edata.ptr)
		@address = address
		@edata, @edata_ptr = edata, edata_ptr
		@list = []
		@backtracked_for = []
	end

	# splits the current block into a new one with all di from offset off (di.block_offset) to end
	# caller is responsible for rebacktracing new.bt_for to regenerate correct old.bt.b_off/new.bt
	def split(off)
		raise "invalid split #{off}" if off == 0 or not idx = @list.index(@list.find { |di| di.block_offset == off })
		new_b = self.class.new(Expression[@address, :+, off].reduce, @edata, @edata_ptr + off)
		new_b.add_di @list.delete_at(idx) while @list[idx]
		new_b.to_normal, @to_normal = to_normal, new_b.to_normal
		new_b.to_subfuncret, @to_subfuncret = to_subfuncret, new_b.to_subfuncret
		new_b.subfunction,   @subfunction =   subfunction,   new_b.subfunction
		new_b.add_from @list.last.address
		add_to new_b.address
		@backtracked_for.delete_if { |btt|
			if btt.block_offset and btt.block_offset >= off
				btt.block_offset -= off
				new_b.backtracked_for << btt
				true
			end
		}
		new_b
	end

	# adds a decodedinstruction to the block list, updates di.block and di.block_offset
	def add_di(di)
		di.block = self
		di.block_offset = (@list.empty? ? 0 : (@list.last.block_offset + @list.last.bin_length))
		@list << di
	end

	# adds an address to the from_normal/from_subfuncret list
	def add_from(addr, subfuncret=false)
		if subfuncret: add_from_subfuncret addr
		else add_from_normal addr
		end
	end
	
	# iterates over every from address, yields [address, (bool)from_subfuncret]
	def each_from
		each_from_normal { |a| yield a }
		each_from_subfuncret { |a| yield a, true }
	end

	def add_to(addr, subfuncret=false)
		if subfuncret: add_to_subfuncret addr
		else add_to_normal addr
		end
	end

	def each_to
		each_to_normal { |a| yield a }
		each_to_subfuncret { |a| yield a, true }
	end
end

# a factorized subfunction as seen by the disassembler
class DecodedFunction
	extend AccessorList
	
	# when backtracking an instruction that calls us, use this binding and then the instruction's
	attr_accessor :backtrace_binding
	# same as InstructionBlock#backtracked_for
	# includes the expression responsible of the function return (eg [esp] on ia32)
	attr_accessor :backtracked_for
	# addresses of instruction causing the function to return
	attr_accessor_list :return_address
	# a proc called for dynamic backtrace_binding generation
	# XXX TODO handle propagation (eg GetProcAddress thunk)
	attr_accessor :btbind_callback
	# a proc called for dynamic backtracked_for
	attr_accessor :btfor_callback

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
class Indirection
	# Expression (the pointer)
	attr_accessor :target
	# length in bytes of data referenced
	attr_accessor :len
	# address of the instruction who generated the indirection
	attr_accessor :origin

	def initialize(target, len, origin)
		@target, @len, @origin = target, len, origin
	end

	def reduce
		ptr = Expression[@target.reduce]
		(ptr == Expression::Unknown) ? ptr : Indirection.new(ptr, @len, @origin)
	end
	alias reduce_rec reduce

	def bind(h)
		if r = h[self]: r
		else Indirection.new(@target.bind(h), @len, @origin)
		end
	end

	def hash ; @target.hash^@len end
	def eql?(o) o.class == self.class and [o.target, o.len] == [@target, @len] end
	alias == eql?

	def externals
		[self]
	end

	def to_s
		qual = {1 => 'byte', 2 => 'word', 4 => 'dword'}[@len] || "_#{len*8}bits"
		"#{qual} ptr [#{target}]"
	end

	# returns the complexity of the expression (number of externals +1 per indirection)
	def complexity
		1+@target.complexity
	end
end

class Expression
	# returns the complexity of the expression (number of externals +1 per indirection)
	def complexity
		externals.map { |e| e.respond_to?(:complexity) ? e.complexity : 1 }.inject(0) { |a, b| a+b }
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

	# returns a ::String containing +len+ bytes from self.ptr, advances ptr
	# bytes from rawsize to virtsize are returned as zeroes
	# ignores self.relocations
	def read(len=@virtsize-@ptr)
		str = ''
		if @ptr < @data.length
			str << @data[@ptr, len]
		end
		@ptr += len
		str.ljust(len, "\0")
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
			puts "W: Immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect} (wanted #{type.inspect})" if $VERBOSE
		end
		Expression.decode_imm(read(Expression::INT_SIZE[type]/8), type, endianness)
	end
end

class Expression
	def self.decode_imm(str, type, endianness)
                val = 0
                case endianness
                when :little : str.reverse
		when :big : str
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
		Expression[value.bind(di.backtrace_binding ||= backtrace_binding(di)).reduce]
	end

	# returns a list of Expressions/Integer to backtrace to find an execution target
	def get_xrefs_x(dasm, di)
	end

	# returns a list of [type, address, len]
	def get_xrefs_rw(dasm, di)
		b = di.backtrace_binding ||= backtrace_binding(di)
		find_ind = proc { |list| (list + list.grep(Expression).map { |e| e.externals }.flatten).grep(Indirection) }
		r = b.values
		w = b.keys
		x = get_xrefs_x(dasm, di)
		r |= x if x
		find_ind[r].map { |e| [:r, e.target, e.len] } + find_ind[w].map { |e| [:w, e.target, e.len] }
	end

	# checks if the expression corresponds to a function return value with the instruction
	# (eg di == 'call something' and expr == [esp])
	def backtrace_is_function_return(expr, di=nil)
	end

	# updates f.backtrace_binding when a new return address has been found
	# TODO update also when anything changes inside the function (new loop found etc) - use backtracked_for ?
	def backtrace_update_function_binding(dasm, faddr, f, retaddr)
	end

	# returns if the expression is an address on the stack
	# (to avoid trying to backtrace its absolute address until we found function boundaries)
	def backtrace_is_stack_address(expr)
	end

	# updates the instruction arguments: replace an expression with another (eg when a label is renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression: Expression[a.bind(old => new).reduce]
			else a
			end
		}
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
	# number of blocks to backtrace before aborting if no result is found (defaults to class.backtrace_maxblocks, 50 by default)
	attr_accessor :backtrace_maxblocks
	# maximum backtrace length for :r/:w, defaults to backtrace_maxblocks
	attr_accessor :backtrace_maxblocks_data
	# a cparser that parsed some C header files, prototypes are converted to DecodedFunction when jumped to
	attr_accessor :c_parser

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
		@backtrace_maxblocks = @@backtrace_maxblocks
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
		when nil: @xrefs[addr] = x
		when x
		when ::Array: @xrefs[addr] |= [x]
		else @xrefs[addr] = [@xrefs[addr], x]
		end
	end

	# yields each xref to a given address, optionnaly restricted to a type
	def each_xref(addr, type=nil)
		addr = normalize addr
		case @xrefs[addr]
		when nil
		when ::Array: @xrefs[addr].each { |x| yield x if not type or x.type == type }
		else yield @xrefs[addr] if not type or @xrefs[addr].type == type
		end
	end

	# returns the canonical form of addr (absolute address integer or label of start of section + section offset)
	def normalize(addr)
		return :default if addr == :default
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

	# returns the label at the specified address, creates it if needed using the specified prefix (updates prog_binding)
	# renames it if the old matches one rewritepfx + addr
	# returns nil if the address is not known and is not a string
	def label_at(addr, base='xref', *rewritepfx)
		e, b = get_section_at(addr)
		if not e
			return case addr
			when ::String: addr
			when Expression: addr.rexpr if not addr.lexpr and addr.op == :+ and addr.rexpr.kind_of?(::String)
			end
		end
		addrstr = '_%04x' % (addr.kind_of?(Expression) ? addr.rexpr.kind_of?(::Integer) ? addr.rexpr : 0 : addr)
		if not l = e.inv_export[e.ptr]
			l = @program.new_label(base + addrstr)
			e.add_export l, e.ptr
			@prog_binding[l] = Expression[b, :+, e.ptr].reduce
		elsif rewritepfx.find { |p| base != p and p+addrstr == l }
			newl = @program.new_label(base + addrstr)
			rename_label l, newl
			l = newl
		end
		l
	end

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
			when old: at[0] = new
			when Expression: at[0] = at[0].bind(old => new)
			end
		}
	end

	# decodes instructions from an entrypoint, (tries to) follows code flow
	def disassemble(*entrypoints)
		begin
		loop do
			if @addrs_todo.empty?
				break if not ep = entrypoints.shift
				label_at(normalize(ep), 'entrypoint')
				@addrs_todo << ep
			end
			while not @addrs_todo.empty?
				disassemble_step
			end
		end
		ensure
		post_disassemble
		end
		self
	end

	def post_disassemble
		detect_thunks
		@decoded.each_value { |di|
			next if not di.opcode.props[:saveip]
			di.add_comment 'noreturn' if not di.block.to_subfuncret
		}
		@function.each { |addr, f|
			next if not di = @decoded[addr]
			di.add_comment f.backtrace_binding.map { |k, v| "#{k} -> #{v}" }.sort.join(', ')
		} if $VERBOSE
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

		return if from == :default or from == Expression::Unknown

		puts "disassemble_step #{Expression[addr]} #{Expression[from] if from} #{from_subfuncret}  #{@addrs_todo.length}" if $DEBUG

		addr = normalize(addr)

		if di = @decoded[addr]
			split_block(di.block, di.block_offset) if di.block_offset != 0	# this updates di.block
			di.block.add_from(from, from_subfuncret)
			bf = di.block
		elsif bf = @function[addr]
		elsif s = get_section_at(addr)
			block = InstructionBlock.new(Expression[s[1], :+, s[0].ptr].reduce, s[0])
			block.add_from(from, from_subfuncret) if from
			disassemble_block(block)
		elsif from and c_parser and addr.kind_of? Expression and addr.op == :+ and not addr.lexpr and addr.rexpr.kind_of? ::String and
				s = c_parser.toplevel.symbol[addr.rexpr] and s.type.untypedef.kind_of? C::Function
			bf = @function[addr] = @cpu.decode_c_function_prototype(@c_parser, s)
		elsif from
			if bf = @function[:default]
				puts "using default function for #{Expression[addr]} from #{Expression[from]}" if $VERBOSE
				if addr.kind_of? Expression and not addr.lexpr and addr.op == :+ and addr.rexpr.kind_of? ::String
					@function[addr] = @function[:default].dup
				else
					addr = :default
				end
			else
				puts "not disassembling unknown address #{Expression[addr]} from #{Expression[from]}" if $VERBOSE
			end
			add_xref(addr, Xref.new(:x, from))
			add_xref(Expression::Unknown, Xref.new(:x, from))
		else
			puts "not disassembling unknown address #{Expression[addr]}" if $VERBOSE
		end

		if bf and from
			if bf.kind_of? DecodedFunction
				bff = bf.get_backtracked_for(self, addr, from)
			else
				bff = bf.backtracked_for
			end
		end
		bff.each { |btt|
			next if btt.block_offset
			next if backtrace_check_funcret(btt, addr, from)
			backtrace(btt.expr, from,
				  :include_start => true, :from_subfuncret => from_subfuncret,
				  :origin => btt.origin, :type => btt.type, :len => btt.len,
				  :detached => btt.detached, :maxdepth => btt.maxdepth)
		} if bff
	end

	# splits an InstructionBlock, updates the blocks backtracked_for
	def split_block(block, offset)
		new_b = block.split offset
		todo = []	# array of [expr, off]
		new_b.backtracked_for.each { |btt|
			backtrace(btt.expr, Expression[new_b.address, :+, btt.block_offset].reduce,
				  :include_start => !btt.exclude_instr, :from_subfuncret => btt.from_subfuncret,
				  :origin => btt.origin, :type => btt.type, :len => btt.len, :snapshot_addr => block.address, 
				  :detached => btt.detached, :maxdepth => btt.maxdepth)
		}
		new_b
	end

	# disassembles a new instruction block at block.address (must be normalized)
	def disassemble_block(block)
		raise if not block.list.empty?
		di_addr = block.address

		# try not to run for too long
		# loop usage: break if the block continues to the following instruction, else return
		100.times {
			# check collision into a known block
			break if @decoded[di_addr]

			# decode instruction
			block.edata.ptr = block.edata_ptr + Expression[di_addr, :-, block.address].reduce
			if not di = @cpu.decode_instruction(block.edata, di_addr)
				puts "unknown instruction to decode at #{Expression[di_addr]}" if $VERBOSE
				return
			end

			@decoded[di_addr] = di
			block.add_di di

			# check self-modifying code
			if @check_smc
				# uncomment to check for unaligned rewrites
				#(-7...di.bin_length).each { |off|
				waddr = di_addr		#Expression[di_addr, :+, off].reduce
				each_xref(waddr, :w) { |x|
					#next if off + x.len < 0
					puts "W: disasm: self-modifying code at #{Expression[waddr]}" if $VERBOSE
					di.add_comment "overwritten by #{@decoded[x.origin] || Expression[x.origin]}"
					return
				}
				#}
			end

			breakafter = false
			# trace xrefs
			# PE SEH needs rw to be checked before x (for xrefs :w)
			@program.get_xrefs_rw(self, di).each { |type, ptr, len|
				backtrace(ptr, di_addr, :origin => di_addr, :type => type, :len => len).each { |xaddr|
					next if xaddr == Expression::Unknown
					# uncomment to check for unaligned rewrites
					if @check_smc and type == :w
						#len.times { |off|
						waddr = xaddr	#Expression[xaddr, :+, off].reduce
						if wdi = @decoded[normalize(waddr)]
							puts "W: disasm: #{di} overwrites #{wdi}" if $VERBOSE
							wdi.add_comment "overwritten by #{di}"
						end
						#}
					end
				}
			}
			@program.get_xrefs_x(self, di).each { |expr|
				if backtrace(expr, di_addr, :origin => di_addr, :type => :x).length > 0
					breakafter = true
				end
			}

			return if di.opcode.props[:stopexec]

			di_addr = Expression[di_addr, :+, di.bin_length].reduce

			break if breakafter
		}

		block.add_to di_addr
		@addrs_todo << [di_addr, block.list.last.address]
		block
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
	#  from_subfuncret is a bool specifying if addr points to a decodedinstruction that calls its block.subfunctions
	#  stopaddr is an [array of] address of instruction, the backtrace will stop just after executing it
	#  maxdepth is the maximum depth (in blocks) for each backtrace branch.
	#  (defaults to dasm.backtrace_maxblocks, which defaults do Dasm.backtrace_maxblocks)
	def backtrace_walk(obj, addr, include_start, from_subfuncret, stopaddr, maxdepth)
		start_addr = normalize(addr)
		stopaddr = [stopaddr] if stopaddr and not stopaddr.kind_of? ::Array

		# array of [obj, addr, from_subfuncret, loopdetect]
		# loopdetect is an array of [obj, addr, from_subfuncret] of each end of block encountered
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
			elsif w_di = @decoded[w_addr] and w_di.block_offset != 0
				prevdi = w_di.block.list[w_di.block.list.index(w_di)-1]
				todo << [w_obj, prevdi.address, false, w_loopdetect]
			elsif w_di
				next if done.include? [w_obj, w_addr]
				done << [w_obj, w_addr]
				hadsomething = false
				w_di.block.each_from { |f_addr, f_func|
					hadsomething = true
					if l = w_loopdetect.find { |l_obj, l_addr, l_func| l_addr == f_addr and l_func == f_func }
						f_obj = yield(:loop, w_obj, :looptrace => w_loopdetect[w_loopdetect.index(l)..-1], :loopdetect => w_loopdetect)
						if f_obj and f_obj != w_obj	# should avoid infinite loops
							f_loopdetect = w_loopdetect[0...w_loopdetect.index(l)]
						end
					else
						f_obj = yield(:up, w_obj, :from => w_addr, :to => f_addr, :sfret => f_func, :loopdetect => w_loopdetect)
					end
					next if f_obj == false
					f_obj ||= w_obj
					f_loopdetect ||= w_loopdetect
					todo << [f_obj, f_addr, f_func, f_loopdetect + [[f_obj, f_addr, f_func]] ]
				}
				yield :end, w_obj, :addr => w_addr, :loopdetect => w_loopdetect if not hadsomething
			elsif @function[w_addr] and w_addr != :default and w_addr != Expression::Unknown
				next if done.include? [w_obj, w_addr]
				oldlen = todo.length
				each_xref(w_addr, :x) { |x|
					if l = w_loopdetect.find { |l_obj, l_addr, l_func| l_addr == w_addr }
						f_obj = yield(:loop, w_obj, :looptrace => w_loopdetect[w_loopdetect.index(l)..-1], :loopdetect => w_loopdetect)
						if f_obj and f_obj != w_obj
							f_loopdetect = w_loopdetect[0...w_loopdetect.index(l)]
						end
					else
						f_obj = yield(:up, w_obj, :from => w_addr, :to => x.origin, :sfret => false, :loopdetect => w_loopdetect)
					end
					next if f_obj == false
					f_obj ||= w_obj
					f_loopdetect ||= w_loopdetect
					todo << [f_obj, x.origin, false, f_loopdetect + [[f_obj, x.origin, false]] ]
				}
				yield :end, w_obj, :addr => w_addr, :loopdetect => w_loopdetect if todo.length == oldlen
			else
				yield :unknown_addr, w_obj, :addr => w_addr, :loopdetect => w_loopdetect
			end
		}

		if include_start
			todo << [obj, start_addr, from_subfuncret, []]
		else
			walk_up[obj, start_addr, []]
		end

		while not todo.empty?
			obj, addr, func, loopdetect = todo.pop
			di = @decoded[addr]
			if func
				raise "backtrace #{Expression[addr]}: bad from_subfuncret" if not di or not di.block.subfunction
				di.block.each_subfunction { |sf|
					s_obj = yield(:func, obj, :func => @function[sf], :funcaddr => sf, :addr => addr, :loopdetect => loopdetect)
					next if s_obj == false
					s_obj ||= obj
					if l = loopdetect.find { |l_obj, l_addr, l_func| addr == l_addr and not l_func }
						l_obj = yield(:loop, s_obj, :looptrace => loopdetect[loopdetect.index(l)..-1], :loopdetect => loopdetect)
						if l_obj and l_obj != s_obj
							s_loopdetect = loopdetect[0...loopdetect.index(l)]
						end
						next if l_obj == false
						s_obj = l_obj if l_obj
					end
					s_loopdetect ||= loopdetect
					todo << [s_obj, addr, false, s_loopdetect + [[s_obj, addr, false]] ]
				}
			elsif di
				di.block.list[0..di.block.list.index(di)].reverse_each { |di|
					if stopaddr and ea = Expression[di.block.address, :+, di.block_offset+di.bin_length].reduce and stopaddr.include?(ea)
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

	# backtraces the value of an expression from start_addr
	# updates blocks backtracked_for if type is set
	# uses backtrace_walk
	# all values returned are from backtrace_check_found (which may generate xrefs, labels, addrs to dasm)
	# options:
	#  :include_start => start backtracking including start_addr
	#  :from_subfuncret => 
	#  :origin => origin to set for xrefs when resolution is successful
	#  :type => xref type (:r, :w, :x, :addr)
	#  :len => xref len (for :r/:w)
	#  :snapshot_addr => addr (or array of) where the backtracker should stop
	#   if a snapshot_addr is given, values found are ignored if continuing the backtrace does not get to it (eg maxdepth/unk_addr/end)
	#  :maxdepth => maximum number of blocks to backtrace
	#  :detached => true if backtracking type :x and the result should not have from = origin set in @addrs_todo
	#  :max_complexity{_data} => maximum complexity of the expression before aborting its backtrace
	# XXX origin/type/len/detached -> BacktraceTrace ?
	def backtrace(expr, start_addr, nargs={})
		include_start   = nargs.delete :include_start
		from_subfuncret = nargs.delete :from_subfuncret
		origin          = nargs.delete :origin
		type            = nargs.delete :type
		len             = nargs.delete :len
		snapshot_addr   = nargs.delete :snapshot_addr
		maxdepth        = nargs.delete(:maxdepth) || @backtrace_maxblocks
		detached        = nargs.delete :detached
		max_complexity  = nargs.delete(:max_complexity) || 40
		max_complexity_data = nargs.delete(:max_complexity) || 8
		raise ArgumentError, "invalid argument to backtrace #{nargs.keys.inspect}" if not nargs.empty?


		start_addr = normalize(start_addr)
		di = @decoded[start_addr]

		if not snapshot_addr and @cpu.backtrace_is_stack_address(expr)
			puts "  not backtracking stack address #{expr}" if $DEBUG
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
			btt = BacktraceTrace.new(expr, origin, type, len, maxdepth)
			btt.block_offset = di.block_offset
			btt.exclude_instr = true if not include_start
			btt.from_subfuncret = true if from_subfuncret and include_start
			btt.detached = true if detached
			di.block.backtracked_for |= [btt]
		end

		# list of Expression/Integer
		result = []

puts "\nbacktracking #{type} #{expr} from #{di || Expression[start_addr]}" if $DEBUG
		backtrace_walk(expr, start_addr, include_start, from_subfuncret, snapshot_addr, maxdepth) { |ev, expr, h|
			case ev
			when :unknown_addr, :maxdepth
puts "  backtrace end #{ev} #{expr}" if $DEBUG
				result |= [expr] if not snapshot_addr
				@addrs_todo << [expr, (detached ? nil : origin)] if not snapshot_addr and type == :x and origin
			when :end
puts "  backtrace end #{ev} #{expr}" if $DEBUG
				if not snapshot_addr
					result |= [expr]

					btt = BacktraceTrace.new(expr, origin, type, len, maxdepth-h[:loopdetect].length)
					btt.detached = true if detached
					@decoded[h[:addr]].block.backtracked_for |= [btt] if @decoded[h[:addr]]
					@function[h[:addr]].backtracked_for |= [btt] if @function[h[:addr]] and h[:addr] != :default
					@addrs_todo << [expr, (detached ? nil : origin)] if type == :x and origin
				end
			when :stopaddr
puts "  backtrace end #{ev} #{expr}" if $DEBUG
				result |= ((expr.kind_of?(StoppedExpr)) ? expr.exprs : [expr])
			when :loop
				next false if expr.kind_of? StoppedExpr
				t = h[:looptrace]
				oldexpr = t[0][0]
				next false if expr == oldexpr		# unmodifying loop
				puts "  bt loop at #{Expression[t[0][1]]}: #{oldexpr} => #{expr} (#{t.map { |z| Expression[z[1]] }.join(' <- ')})" if $DEBUG
				false
			when :up
				next if expr.kind_of? StoppedExpr
				if origin and type
					# update backtracked_for
					btt = BacktraceTrace.new(expr, origin, type, len, maxdepth-h[:loopdetect].length)
					btt.detached = true if detached
					@decoded[h[:from]].block.backtracked_for |= [btt] if @decoded[h[:from]]
					@function[h[:from]].backtracked_for |= [btt] if @function[h[:from]] and h[:from] != :default
					if @decoded[h[:to]]
						btt = btt.dup
						btt.block_offset = @decoded[h[:to]].block_offset
						btt.from_subfuncret = true if h[:sfret]
						next false if backtrace_check_funcret(btt, h[:from], h[:to])
						@decoded[h[:to]].block.backtracked_for |= [btt]
					end
				end
				nil
			when :di, :func
				next if expr.kind_of? StoppedExpr
				if not snapshot_addr and @cpu.backtrace_is_stack_address(expr)
puts "  not backtracking stack address #{expr}" if $DEBUG
					next false
				end
oldexpr = expr
				case ev
				when :di: expr = backtrace_emu_instr(h[:di], expr)
				when :func: expr = backtrace_emu_subfunc(h[:func], h[:funcaddr], h[:addr], expr, origin, maxdepth-h[:loopdetect].length)
				if snapshot_addr and snapshot_addr == h[:funcaddr]
					puts "  backtrace: recursive function #{Expression[h[:funcaddr]]}" if $DEBUG
					next false
				end
				end
puts "  backtrace #{h[:di] || Expression[h[:funcaddr]]}  #{oldexpr} => #{expr}" if $DEBUG
				if vals = backtrace_check_found(expr, h[:di], origin, type, len, maxdepth-h[:loopdetect].length, detached)
					if snapshot_addr
						expr = StoppedExpr.new vals
					else
						result |= vals
						next false
					end
				elsif expr.complexity > max_complexity
					puts "  backtrace aborting, expr too complex" if $DEBUG
					next false
				end
				expr
			else raise ev.inspect
			end
		}
puts '  backtrace result: ' + result.map { |r| Expression[r] }.join(', ') if $DEBUG

		result
	end

	# checks if the BacktraceTrace is a call to a subfunction
	# returns true and updates self.addrs_todo
	def backtrace_check_funcret(btt, funcaddr, instraddr)
		if di = @decoded[instraddr] and @function[funcaddr] and btt.type == :x and
				not btt.from_subfuncret and
				@cpu.backtrace_is_function_return(btt.expr) and
				retaddr = backtrace_emu_instr(di, btt.expr) and
				not need_backtrace(retaddr)
puts "  backtrace addrs_todo << #{Expression[retaddr]} from #{di} (funcret)" if $DEBUG
			di.block.add_subfunction funcaddr
			di.block.add_to retaddr, true
			@addrs_todo.unshift [retaddr, instraddr, true]	# dasm inside of the function first
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

	# static resolution of indirections
	def resolve(expr)
		binding = Expression[expr].externals.grep(Indirection).inject(@prog_binding.merge(@old_prog_binding)) { |binding, ind|
			e, b = get_section_at(resolve(ind.target))
			return expr if not e
			binding.merge ind => Expression[ e.decode_imm("u#{8*ind.len}".to_sym, @cpu.endianness) ]
		}
		Expression[expr].bind(binding).reduce
	end

	# returns true if the expression needs more backtrace
	# it checks for the presence of a symbol (not :unknown), which means it depends on some register value
	def need_backtrace(expr)
		return if expr.kind_of? ::Integer or expr == Expression::Unknown
		expr.externals.find { |x|
			case x
			when Indirection: need_backtrace(x.target)
			when ::Symbol: x != :unknown
			# when ::String: not @prog_binding[x]
			end
		}
	end

	# returns an array of expressions, or nil if expr needs more backtrace
	# it needs more backtrace if expr.externals include a Symbol != :unknown (recursed through Indirections too) (symbol == register value)
	# if it need no more backtrace, expr's indirections are recursively resolved
	# xrefs are created, and di args are updated (immediate => label)
	# if type is :x, addrs_todo is updated, and if di starts a block, expr is checked to see if it may be a subfunction return value
	#
	# expr indirection are solved by first finding the value of the pointer, and then rebacktracking for write-type access
	# detached is true if type is :x and from should not be set in addrs_todo (indirect call flow, eg external function callback)
	# if the backtrace ends pre entrypoint, returns the value encoded in the raw binary
	# XXX global variable (modified by another function), exported data, multithreaded app..
	# TODO handle memory aliasing (mov ebx, eax ; write [ebx] ; read [eax])
	# TODO mark things for rebacktrace
	# TODO trace expr evolution through backtrace, to modify immediates to an expr involving label names
	#  eg. mov eax, 42 ; add eax, 4 ; jmp eax  =>  mov eax, some_label-4
	def backtrace_check_found(expr, di, origin, type, len, maxdepth, detached)
		# only entrypoints or block starts called by a :saveip are checked for being a function
		if type == :x and di and di.block_offset == 0 and @cpu.backtrace_is_function_return(expr) and (
			(not di.block.from_normal and not di.block.from_subfuncret) or
			(bool = false ; di.block.each_from_normal { |fn| bool = true if @decoded[fn] and @decoded[fn].opcode.props[:saveip] } ; bool))
			# the actual return address will be found later (after we return nil)
			addr = di.address
			l = label_at(addr, 'sub', 'loc', 'xref')
			if not f = @function[addr]
				f = @function[addr] = DecodedFunction.new
				puts "found new function #{l} at #{Expression[addr]}" if $VERBOSE
				# each_xref(addr, :x) { rebacktrace => to_subfuncret ? }
			end

			if @decoded[origin]
				f.add_return_address origin
				@decoded[origin].add_comment "endsub #{l}"
			end

			f.backtracked_for |= @decoded[addr].block.backtracked_for.find_all { |btt| not btt.block_offset }
			@cpu.backtrace_update_function_binding(self, addr, f, origin)
puts "backtrace function binding for #{l}:", f.backtrace_binding.map { |k, v| " #{k} -> #{v}" }.sort if $DEBUG
		end

		return if need_backtrace(expr)

puts "backtrace #{type} found #{expr} from #{di} orig #{@decoded[origin] || Expression[origin] if origin}" if $DEBUG
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
		result.first.externals.grep(Indirection).uniq.each { |i|
			next_result = []
			backtrace_indirection(i, maxdepth).each { |rr|
				next_result |= result.map { |e| Expression[e.bind(i => rr).reduce] }
			}
			result = next_result
		}

		result.uniq
	end

	# returns the array of values pointer by the indirection at its invocation (ind.origin)
	# first resolves the pointer using backtrace_value, if it does not point in edata keep the original pointer
	# then backtraces from ind.origin until it finds an :w xref origin
	# if no :w access is found, returns the value encoded in the raw section data
	# TODO handle unaligned (partial?) writes
	def backtrace_indirection(ind, maxdepth)
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
				next if x.len != ind.len or not @decoded[x.origin]
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
					puts "   backtrace_indirection for #{ind.target} failed: #{ev}" if $DEBUG
					ret |= [Expression::Unknown]
				when :end
					if not refs.empty? and (expr == true or not need_backtrace(expr))
						if expr == true
							# found a path avoiding the :w xrefs, read the encoded initial value
							ret |= [decode_imm[ptr, ind.len]]
						else
							bd = expr.externals.grep(Indirection).inject({}) { |h, i| h.update i => decode_imm[i.target, i.len] }
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
							puts "backtrace_ind: cannot find :w #{ptr} in xrefs from #{di}" if $VERBOSE
							ret |= [Expression::Unknown]
							next false
						end
						expr = Indirection.new(writes[0][1], ind.len, di.address)
					end
					expr = backtrace_emu_instr(di, expr)
					# may have new indirections... recall bt_value ?
					#if not need_backtrace(expr)
					if expr.externals.all? { |e| @prog_binding[e] or @function[Expression[e].reduce] }
						ret |= backtrace_value(expr, maxdepth-1-h[:loopdetect].length)
						false
					else
						expr
					end
				when :func
					next true if expr == true	# XXX
					expr = backtrace_emu_subfunc(h[:func], h[:funcaddr], h[:addr], expr, ind.origin, maxdepth-h[:loopdetect].length)
					#if not need_backtrace(expr)
					if expr.externals.all? { |e| @prog_binding[e] or @function[Expression[e].reduce] }
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
		n = Expression[label_at(n, base, 'loc', 'xref') || n]

		# update instr args
		# TODO trace expression evolution to allow handling of
		#  mov eax, 28 ; add eax, 4 ; jmp eax
		#  => mov eax, (loc_xx-4)
		if di and not unk # and di.address == origin
			@cpu.replace_instr_arg_immediate(di.instruction, expr, n)
		end

		# add comment
		if type and @decoded[origin] # and not @decoded[origin].instruction.args.include? n
			@decoded[origin].add_comment "#{type}#{len}:#{n}"
		end

		if di and type == :r and (len == 1 or len == 2) and s = get_section_at(n)
			l = s[0].inv_export[s[0].ptr]
			case len
			when 1: str = s[0].read(32).unpack('C*')
			when 2: str = s[0].read(64).unpack('v*')
			end
			str = str.inject('') { |str, c|
				case c
				when 0x20..0x7e, ?\n, ?\r, ?\t: str << c
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

		if type == :x and origin
			origin = nil if detached
			@decoded[origin].block.add_to_normal(n) if @decoded[origin] and not unk
			@addrs_todo << [n, origin]
puts "    backtrace_found: addrs_todo << #{n} from #{Expression[origin] if origin}" if $DEBUG
		end
	end

	# detect and rename thunks
	# a thunk is a location that you can call and that will just forward to an external function
	def detect_thunks
		@function.each_key { |f|
			next if @decoded[f] or not f.kind_of? Expression or f.op != :+ or f.lexpr or not f.rexpr.kind_of? ::String
			each_xref(f, :x) { |xr|
				next if not di = @decoded[xr.origin]
				next if di.block.to_subfuncret or di.block.to_normal != f
				while di and (not @function[di.block.address] or not @xrefs[di.block.address])
					di = @decoded[di.block.from_subfuncret || di.block.from_normal]
					di = nil if di and di.block.to_normal.kind_of? ::Array
				end
				next if not di
				l = label_at(di.block.address)
				next if l[0, 4] != 'sub_'
				puts "found thunk for #{f.rexpr} at #{Expression[di.block.address]}" if $VERBOSE
				label = @program.new_label "thunk_#{f.rexpr}"
				rename_label(l, label)
			}
		}
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
			blockoffs = @decoded.values.map { |di| Expression[di.block.address, :-, addr].reduce if di.block_offset == 0 }.grep(::Integer).sort.reject { |o| o < 0 or o >= edata.length }
			b.call @program.dump_section_header(addr, edata)
			if not dump_data and edata.length > 16*1024 and blockoffs.empty?
				b["// [#{edata.length} data bytes]"]
				next
			end
			unk_off = 0
			# blocks.sort_by { |b| b.addr }.each { |b|
			edata.length.times { |i|
				curaddr = Expression[addr, :+, i].reduce
				if di = @decoded[curaddr] and di.block_offset == 0
					b["\n// ------ overlap (#{unk_off-di.block.edata_ptr}) ------"] if unk_off != di.block.edata_ptr
					dump_block(di.block, &b)
					di = di.block.list.last
					unk_off = i + di.block_offset + di.bin_length
				elsif i >= unk_off
					next_off = blockoffs.find { |bo| bo > i } || edata.length
					if dump_data or next_off - i < 16
						unk_off = dump_data(Expression[addr, :+, unk_off].reduce, edata, unk_off, &b)
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
		xr = []
		each_xref(block.address) { |x|
			case x.type
			when :x: xr << Expression[x.origin]
			when :r, :w: xr << "#{x.type}#{x.len}:#{Expression[x.origin]}"
			end
		}
		if not xr.empty?
			b.call ''
			b.call "// Xrefs: #{xr[0, 8].join(' ')}#{' ...' if xr.length > 8}"
		end
		if @prog_binding.index(block.address)
			b.call '' if xr.empty?
			@prog_binding.each { |name, addr| b.call "#{name}:" if addr == block.address }
		end
		block.list.each { |di|
			block.edata.ptr = block.edata_ptr + di.block_offset
			bin = block.edata.read(di.bin_length).unpack('C*').map { |c| '%02x' % c }.join
			if di.bin_length > 12
				bin = bin[0, 20] + "..<+#{di.bin_length-10}>"
			end
			b.call "    #{di.instruction.to_s.ljust(44)} ; @#{Expression[di.address]}  #{bin}  #{di.comment.sort[0,6].join(' ') if di.comment}"
		}
	end

	# dumps data/labels, honours @xrefs.len if exists
	# dumps one line only
	# stops on end of edata/@decoded/@xref
	# returns the next offset to display
	# TODO array-style data access
	def dump_data(addr, edata, off, &b)
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
			if tmp = @prog_binding.values.find { |a|
				tmp = Expression[a, :-, addr].reduce
				tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
			}
			dups = tmp
			end
			if tmp = @xrefs.keys.find { |a|
				tmp = Expression[a, :-, addr].reduce
				tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
			}
				dups = tmp
			end
			dups /= elemlen
			dups = 1 if dups < 1
			b.call l + "#{dups} dup(?)"
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
			addr = Expression[addr, :+, elemlen].reduce
			if i = (1-elemlen..0).find { |i|
				t = Expression[addr, :+, i].reduce
				@xrefs[t] or @decoded[t] or edata.reloc[edata.ptr+i] or edata.inv_export[edata.ptr+i]
			}
				edata.ptr += i
				addr = Expression[addr, :+, i].reduce
				break
			end
			break if edata.reloc[edata.ptr-elemlen]
		end

		# line of repeated value => dup()
		if vals.length > 8 and vals.uniq.length == 1
			b.call((l << "#{vals.length} dup(#{Expression[vals.first]})").ljust(48) << cmt)
			return edata.ptr
		end

		# recognize strings
		vals = vals.inject([]) { |vals, value|
			if (elemlen == 1 or elemlen == 2)
				case value
				when 0x20..0x7e, 0x0a, 0x0d
					if vals.last.kind_of? ::String: vals.last << value ; vals
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

		b.call((l << vals.join(', ')).ljust(48) << cmt)

		edata.ptr
	end
end
end
