#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


module Metasm

VERSION = 0x0001	# major major minor minor

# superclass for all metasm exceptions
class Exception < RuntimeError ; end
# parse error
class ParseError < Exception ; end
# invalid exeformat signature
class InvalidExeFormat < Exception ; end
# cannot honor .offset specification, reloc fixup overflow
class EncodeError < Exception ; end

# holds context of a processor
# endianness, current mode, opcode list...
class CPU
	attr_accessor :valid_args, :valid_props, :fields_mask
	attr_accessor :endianness, :size
	attr_accessor :generate_PIC
	
	def opcode_list
		@opcode_list ||= init_opcode_list
	end
	def opcode_list=(l) @opcode_list = l end

	def initialize
		@fields_mask = {}
		@valid_args  = []
		@valid_props = [:setip, :saveip, :stopexec]
		@generate_PIC = true
	end

	# returns a hash opcode_name => array of opcodes with this name
	def opcode_list_byname
		@opcode_list_byname ||= opcode_list.inject({}) { |h, o| (h[o.name] ||= []) << o ; h }
	end

	# sets up the C parser : standard macro definitions, type model (size of int etc)
	def tune_cparser(cp)
		cp.send "ilp#@size"
		cp.lexer.define('_STDC', 1) if not cp.lexer.definition['_STDC']
		# TODO cp.lexer.define('BIGENDIAN')
		# TODO gcc -dM -E - </dev/null
		# TODO ExeFormat-specific definitions
	end

	# returns a new & tuned C::Parser
	def new_cparser
		cp = C::Parser.new
		tune_cparser cp
		cp
	end

	# returns a new C::Compiler
	def new_ccompiler(parser, exe=ExeFormat.new)
		exe.cpu ||= self
		C::Compiler.new(parser, exe)
	end
end

# generic CPU, with no instructions, just size/endianness
class UnknownCPU < CPU
	def initialize(size, endianness)
		super()
		@size, @endianness = size, endianness
	end
end

# a cpu instruction 'formal' description
class Opcode
	# the name of the instruction
	attr_accessor :name
	# formal description of arguments (array of cpu-specific symbols)
	attr_accessor :args
	# binary encoding of the opcode (integer for risc, array of bytes for cisc)
	attr_accessor :bin
	# list of bit fields in the binary encoding
	# hash position => field
	# position is bit shift for risc, [byte index, bit shift] for risc
	# field is cpu-specific
	attr_accessor :fields
	# hash of opcode generic properties/restrictions (mostly property => true/false)
	attr_accessor :props
	# binary mask for decoding
	attr_accessor :bin_mask

	def initialize(name)
		@name = name
		@args = []
		@fields = {}
		@props = {}
	end

	def basename
		@name.sub(/\..*/, '')
	end
end

# defines an attribute self.backtrace (array of filename/lineno)
# and a method backtrace_str which dumps this array to a human-readable form
module Backtrace
	# array [file, lineno, file, lineno]
	# if file 'A' does #include 'B' you'll get ['A', linenoA, 'B', linenoB]
	attr_accessor :backtrace

	# builds a readable string from self.backtrace
	def backtrace_str
		Backtrace.backtrace_str(@backtrace)
	end

	# builds a readable backtrace string from an array of [file, lineno, file, lineno, ..]
	def self.backtrace_str(ary)
		return '' if not ary
		i = ary.length
		bt = ''
		while i > 0
			bt << ",\n\tincluded from " if ary[i]
			i -= 2
			bt << "#{ary[i].inspect} line #{ary[i+1]}"
		end
		bt
	end

	def exception(msg='syntax error')
		ParseError.new "at #{backtrace_str}: #{msg}"
	end
end

# an instruction: opcode name + arguments
class Instruction
	# arguments (cpu-specific objects)
	attr_accessor :args
	# hash of prefixes (unused in simple cpus)
	attr_accessor :prefix
	# name of the associated opcode
	attr_accessor :opname
	# reference to the cpu which issued this instruction (used for rendering)
	attr_accessor :cpu

	include Backtrace

	def initialize(cpu, opname=nil, args=[], pfx=nil, backtrace=nil)
		@cpu = cpu
		@opname = opname
		@args = args
		@prefix = pfx if pfx
		@backtrace = backtrace
	end

	# duplicates the argument list and prefix hash
	def dup
		Instruction.new(@cpu, (@opname.dup if opname), @args.dup, (@prefix.dup if prefix), (@backtrace.dup if backtrace))
	end
end

# all kind of data description (including repeated/uninitialized)
class Data
	# maps data type to Expression parameters (signedness/bit size)
	INT_TYPE = {'db' => :u8, 'dw' => :u16, 'dd' => :u32, 'dq' => :u64}

	# an Expression, an Array of Data, a String, or :uninitialized
	attr_accessor :data
	# the data type, from INT_TYPE (TODO store directly Expression parameters ?)
	attr_accessor :type
	# the repetition count of the data parameter (dup constructs)
	attr_accessor :count

	include Backtrace

	def initialize(type, data, count=1, backtrace=nil)
		@data, @type, @count, @backtrace = data, type, count, backtrace
	end
end

# a name for a location
class Label
	attr_accessor :name

	include Backtrace

	def initialize(name, backtrace=nil)
		@name, @backtrace = name, backtrace
	end
end

# alignment directive
class Align
	# the size to align to
	attr_accessor :val
	# the Data used to pad
	attr_accessor :fillwith

	include Backtrace

	def initialize(val, fillwith=nil, backtrace=nil)
		@val, @fillwith, @backtrace = val, fillwith, backtrace
	end
end

# padding directive
class Padding
	# Data used to pad
	attr_accessor :fillwith

	include Backtrace

	def initialize(fillwith=nil, backtrace=nil)
		@fillwith, @backtrace = fillwith, backtrace
	end
end

# offset directive
# can be used to fix padding length or to assert some code/data compiled length
class Offset
	# the assembler will arrange to make this pseudo-instruction
	# be at this offset from beginning of current section
	attr_accessor :val

	include Backtrace

	def initialize(val, backtrace=nil)
		@val, @backtrace = val, backtrace
	end
end

# contiguous/uninterrupted sequence of instructions, chained to other blocks
# TODO
class InstructionBlock
end

# the superclass of all real executable formats
# main methods:
#  self.decode(str) => decodes the file format (imports/relocs/etc), no asm disassembly
#  parse(source) => parses assembler source, fills self.source
#  assemble => assembles self.source in binary sections/segments/whatever
#  encode => builds imports/relocs tables, put all this together, links everything in self.encoded
class ExeFormat
	# array of Data/Instruction/Align/Padding/Offset/Label, populated in parse
	attr_accessor :cursource
	# contains the binary version of the compiled program (EncodedData)
	attr_accessor :encoded
	# reference to the current CPU used (may be nil)
	attr_accessor :cpu
	# hash of labels generated by new_label
	attr_accessor :unique_labels_cache

	# initializes self.cpu, creates an empty self.encoded
	def initialize(cpu=nil)
		@cpu = cpu
		@encoded = EncodedData.new
		@unique_labels_cache = {}
	end

	# return the label name corresponding to the specified offset of the encodeddata, creates it if necessary
	def label_at(edata, offset, base = '')
		if not l = edata.inv_export[offset]
			edata.add_export(l = new_label(base), offset)
		end
		l
	end

	# creates a new label, that is guaranteed to never be returned again as long as this object (ExeFormat) exists
	def new_label(base = '')
		base = base.dup.tr('^a-zA-Z0-9_', '_')
		# use %x instead of to_s(16) for negative values
		base = (base << '_uuid' << ('%08x' % base.object_id)).freeze if base.empty? or @unique_labels_cache[base]
		@unique_labels_cache[base] = true
		base
	end

	# share self.unique_labels_cache with other, checks for conflicts, returns self
	def share_namespace(other)
		return self if other.unique_labels_cache.equal? @unique_labels_cache
		raise "share_ns #{(other.unique_labels_cache.keys & @unique_labels_cache.keys).inspect}" if !(other.unique_labels_cache.keys & @unique_labels_cache.keys).empty?
		@unique_labels_cache.update other.unique_labels_cache
		other.unique_labels_cache = @unique_labels_cache
		self
	end
end

# superclass for classes similar to Expression
# must define #bind, #reduce_rec, #match_rec, #externals
class ExpressionType
	def +(o) Expression[self, :+, o].reduce end
	def -(o) Expression[self, :-, o].reduce end
end

# handle immediate values, and arbitrary arithmetic/logic expression involving variables
# boolean values are treated as in C : true is 1, false is 0
# TODO replace #type with #size => bits + #type => [:signed/:unsigned/:any/:floating]
# TODO handle floats
class Expression < ExpressionType
	INT_SIZE = {:u8 => 8,    :u16 => 16,     :u32 => 32, :u64 => 64,
		    :i8 => 8,    :i16 => 16,     :i32 => 32, :i64 => 64,
		    :a8 => 8,    :a16 => 16,     :a32 => 32, :a64 => 64
	}
	INT_MIN  = {:u8 => 0,    :u16 => 0,      :u32 => 0, :u64 => 0,
		    :i8 =>-0x80, :i16 =>-0x8000, :i32 =>-0x80000000, :i64 => -0x8000_0000_0000_0000,
	}
	INT_MAX  = {:u8 => 0xff, :u16 => 0xffff, :u32 => 0xffffffff, :u64 => 0xffff_ffff_ffff_ffff,
		    :i8 => 0x7f, :i16 => 0x7fff, :i32 => 0x7fffffff, :i64 => 0x7fff_ffff_ffff_ffff,
	}
	# :a types allow silent truncating on overflow
	INT_MIN[:a8] = INT_MIN[:a16] = INT_MIN[:a32] = INT_MIN[:a64] = -1/0.0
	INT_MAX[:a8] = INT_MAX[:a16] = INT_MAX[:a32] = INT_MAX[:a64] =  1/0.0

	# alternative constructor
	# in operands order, and allows nesting using sub-arrays
	# ex: Expression[[:-, 42], :*, [1, :+, [4, :*, 7]]]
	# with a single argument, return it if already an Expression, else construct a new one (using unary +/-)
	def self.[](l, op = nil, r = nil)
		raise ArgumentError, 'invalid Expression[nil]' if not l and not r and not op
		return l if l.kind_of? Expression and not op
		l, op, r = nil, :-, -l if not op and l.kind_of? ::Numeric and l < 0
		l, op, r = nil, :+, l  if not op
		l, op, r = nil, l, op  if not r
		l = self[*l] if l.kind_of? ::Array
		r = self[*r] if r.kind_of? ::Array
		new(op, r, l)
	end


	# checks if a given Expression/Integer is in the type range
	# returns true if it is, false if it overflows, and nil if cannot be determined (eg unresolved variable)
	def self.in_range?(val, type)
		val = val.reduce if val.kind_of? self
		return unless val.kind_of? ::Numeric

		if INT_MIN[type]
			val == val.to_i and
			val >= INT_MIN[type] and val <= INT_MAX[type]
		end
	end

	# casts an unsigned value to a two-complement signed if the sign bit is set
	def self.make_signed(val, bitlength)
		if val.kind_of? Integer
			val = val - (1 << bitlength) if val >> (bitlength - 1) == 1
		end
		val
	end

	# the operator (symbol)
	attr_accessor :op
	# the lefthandside expression (nil for unary expressions)
	attr_accessor :lexpr
	# the righthandside expression
	attr_accessor :rexpr

	# basic constructor
	# XXX funny args order, you should use +Expression[]+ instead
	def initialize(op, rexpr, lexpr)
		raise ArgumentError, "Expression: invalid arg order: #{[lexpr, op, rexpr].inspect}" if not op.kind_of? ::Symbol
		@op, @lexpr, @rexpr = op, lexpr, rexpr
	end

	# recursive check of equity using #==
	# will not match 1+2 and 2+1
	def ==(o)
		# shortcircuit recursion
		o.object_id == object_id or (o.class == self.class and [o.op, o.rexpr, o.lexpr] == [@op, @rexpr, @lexpr])
	end

	# make it useable as Hash key (see +==+)
	def hash
		[@lexpr, @op, @rexpr].hash
	end
	alias eql? ==

	# returns a new Expression with all variables found in the binding replaced with their value
	# does not check the binding's key class except for numeric
	# calls lexpr/rexpr #bind if they respond_to? it
	def bind(binding = {})
		if binding[self]
			return binding[self].dup
		end

		l, r = @lexpr, @rexpr
		if l and binding[l]
			raise "internal error - bound #{l.inspect}" if l.kind_of? ::Numeric
			l = binding[l]
		elsif l.kind_of? ExpressionType
			l = l.bind(binding)
		end
		if r and binding[r]
			raise "internal error - bound #{r.inspect}" if r.kind_of? ::Numeric
			r = binding[r]
		elsif r.kind_of? ExpressionType
			r = r.bind(binding)
		end
		Expression[l, @op, r]
	end

	# bind in place (replace self.lexpr/self.rexpr with the binding value)
	# only recurse with Expressions (does not use respond_to?)
	def bind!(binding = {})
		if @lexpr.kind_of?(Expression)
			@lexpr.bind!(binding)
		elsif @lexpr
			@lexpr = binding[@lexpr] || @lexpr
		end
		if @rexpr.kind_of?(Expression)
			@rexpr.bind!(binding)
		elsif @rexpr
			@rexpr = binding[@rexpr] || @rexpr
		end
		self
	end

	# reduce_lambda is a callback called after the standard reduction procedure for custom algorithms
	# the lambda may return a new expression or nil (to keep the old expr)
	# exemple: lambda { |e| e.lexpr if e.kind_of? Expression and e.op == :& and e.rexpr == 0xffff_ffff }
	# returns old lambda
	def self.reduce_lambda(&b)
		old = @@reduce_lambda
		@@reduce_lambda = b if block_given?
		old
	end
	def self.reduce_lambda=(p)
		@@reduce_lambda = p
	end
	@@reduce_lambda = nil

	# returns a simplified copy of self
	# can return an +Expression+ or a +Numeric+, may return self
	# see +reduce_rec+ for simplifications description
	# if given a block, it will temporarily overwrite the global @@reduce_lambda XXX THIS IS NOT THREADSAFE
	def reduce(&b)
		begin
			old_rp, @@reduce_lambda = @@reduce_lambda, b if b
			ret = case e = reduce_rec
			when Expression, Numeric; e
			else Expression[e]
			end
		ensure
			@@reduce_lambda = old_rp if b
		end
		ret
	end

	# resolves logic operations (true || false, etc)
	# computes numeric operations (1 + 3)
	# expands substractions to addition of the opposite
	# reduces double-oppositions (-(-1) => 1)
	# reduces addition of 0 and unary +
	# canonicalize additions: put variables in the lhs, descend addition tree in the rhs => (a + (b + (c + 12)))
	# make formal reduction if finds somewhere in addition tree (a) and (-a)
	def reduce_rec
		l = @lexpr.kind_of?(ExpressionType) ? @lexpr.reduce_rec : @lexpr
		r = @rexpr.kind_of?(ExpressionType) ? @rexpr.reduce_rec : @rexpr

		v =
		if r.kind_of?(::Numeric) and (l == nil or l.kind_of?(::Numeric))
			# calculate numerics
			if [:'&&', :'||', :'>', :'<', :'>=', :'<=', :'==', :'!='].include?(@op)
				# bool expr
				raise 'internal error' if not l
				case @op
				when :'&&'; (l != 0) && (r != 0)
				when :'||'; (l != 0) || (r != 0)
				when :'>' ; l > r
				when :'>='; l >= r
				when :'<' ; l < r
				when :'<='; l <= r
				when :'=='; l == r
				when :'!='; l != r
				end ? 1 : 0
			elsif not l
				case @op
				when :'!'; (r == 0) ? 1 : 0
				when :+;  r
				when :-; -r
				when :~; ~r
				end
			else
				# use ruby evaluator
				l.send(@op, r)
			end

		elsif @op == :'&&'
			if l == 0	# shortcircuit eval
				0
			elsif l == 1
				Expression[r, :'!=', 0].reduce_rec
			elsif r == 0	# (no sideeffects) && 0 => 0
				sideeffect = lambda { |e|
					if e.kind_of? Expression
						not [:+, :-, :*, :/, :&, :|, :^, :>, :<, :>>, :<<, :'==', :'!=', :<=, :>=, :'&&', :'||'].include?(e.op) or
						sideeffect[e.lexpr] or sideeffect[e.rexpr]
					elsif e.kind_of? ExpressionType
						true	# fail safe
					else
						false
					end
				}
				0 if not sideeffect[l]
			end
		elsif @op == :'||'
			if l.kind_of? ::Numeric and l != 0	# shortcircuit eval
				1
			elsif l == 0
				Expression[r, :'!=', 0].reduce_rec
			elsif r == 0
				Expression[l, :'!=', 0].reduce_rec
			end
		elsif @op == :>> or @op == :<<
			if l == 0; 0
			elsif r == 0; l
			elsif l.kind_of? Expression and l.op == @op
				Expression[l.lexpr, @op, [l.rexpr, :+, r]].reduce_rec
			# XXX (a >> 1) << 1  !=  a (lose low bit)
			# XXX (a << 1) >> 1  !=  a (with real cpus, lose high bit)
			# (a | b) << i
			elsif r.kind_of? Integer and l.kind_of? Expression and [:&, :|, :^].include? l.op
				Expression[[l.lexpr, @op, r], l.op, [l.rexpr, @op, r]].reduce_rec
			end
		elsif @op == :'!'
			if r.kind_of? Expression and op = {:'==' => :'!=', :'!=' => :'==', :< => :>=, :> => :<=, :<= => :>, :>= => :<}[r.op]
				Expression[r.lexpr, op, r.rexpr].reduce_rec
			end
		elsif @op == :==
			if l == r; 1
			elsif r == 0 and l.kind_of? Expression and op = {:'==' => :'!=', :'!=' => :'==', :< => :>=, :> => :<=, :<= => :>, :>= => :<}[l.op]
				Expression[l.lexpr, op, l.rexpr].reduce_rec
			elsif r == 1 and l.kind_of? Expression and op = {:'==' => :'!=', :'!=' => :'==', :< => :>=, :> => :<=, :<= => :>, :>= => :<}[l.op]
				l
			end
		elsif @op == :'!='
			if l == r; 0
			end
		elsif @op == :^
			if l == :unknown or r == :unknown; :unknown
			elsif l == 0; r
			elsif r == 0; l
			elsif l == r; 0
			elsif r == 1 and l.kind_of? Expression and [:'==', :'!=', :<, :>, :<=, :>=].include? l.op
				Expression[nil, :'!', l].reduce_rec
			elsif l.kind_of? Expression and l.op == :^
				# a^(b^c) => (a^b)^c
				Expression[l.lexpr, :^, [l.rexpr, :^, r]].reduce_rec
			elsif r.kind_of? Expression and r.op == :^
				# (a^b)^a => b
				if    r.rexpr == l; r.lexpr
				elsif r.lexpr == l; r.rexpr
				end
			elsif l.kind_of? Integer; Expression[r, @op, l].reduce_rec
			elsif l.kind_of? Expression and l.op == @op; Expression[l.lexpr, @op, [l.rexpr, @op, r]].reduce_rec
			end
		elsif @op == :&
			if l == 0 or r == 0; 0
			elsif r == 1 and l.kind_of? Expression and [:'==', :'!=', :<, :>, :<=, :>=].include? l.op
				l
			elsif l == r; l
			elsif l.kind_of? Integer; Expression[r, @op, l].reduce_rec
			elsif l.kind_of? Expression and l.op == @op; Expression[l.lexpr, @op, [l.rexpr, @op, r]].reduce_rec
			# (a ^| b) & i
			elsif l.kind_of? Expression and [:|, :^].include? l.op and r.kind_of? Integer
				Expression[[l.lexpr, :&, r], l.op, [l.rexpr, :&, r]].reduce_rec
			# rol/ror composition
			elsif r.kind_of? ::Integer and l.kind_of? Expression and l.op == :|
				m = Expression[[['var', :sh_op, 'amt'], :|, ['var', :inv_sh_op, 'inv_amt']], :&, 'mask']
				if vars = Expression[l, :&, r].match(m, 'var', :sh_op, 'amt', :inv_sh_op, 'inv_amt', 'mask') and vars[:sh_op] == {:>> => :<<, :<< => :>>}[ vars[:inv_sh_op]] and
				   ((vars['amt'].kind_of?(::Integer) and  vars['inv_amt'].kind_of?(::Integer) and ampl = vars['amt'] + vars['inv_amt']) or
				    (vars['amt'].kind_of? Expression and vars['amt'].op == :% and vars['amt'].rexpr.kind_of? ::Integer and
				     vars['inv_amt'].kind_of? Expression and vars['inv_amt'].op == :% and vars['amt'].rexpr == vars['inv_amt'].rexpr and ampl = vars['amt'].rexpr)) and
				   vars['mask'].kind_of?(::Integer) and vars['mask'] == (1<<ampl)-1 and vars['var'].kind_of? Expression and	# it's a rotation
				  ivars = vars['var'].match(m, 'var', :sh_op, 'amt', :inv_sh_op, 'inv_amt', 'mask') and ivars[:sh_op] == {:>> => :<<, :<< => :>>}[ivars[:inv_sh_op]] and
				   ((ivars['amt'].kind_of?(::Integer) and  ivars['inv_amt'].kind_of?(::Integer) and ampl = ivars['amt'] + ivars['inv_amt']) or
				    (ivars['amt'].kind_of? Expression and ivars['amt'].op == :% and ivars['amt'].rexpr.kind_of? ::Integer and
				     ivars['inv_amt'].kind_of? Expression and ivars['inv_amt'].op == :% and ivars['amt'].rexpr == ivars['inv_amt'].rexpr and ampl = ivars['amt'].rexpr)) and
				   ivars['mask'].kind_of?(::Integer) and ivars['mask'] == (1<<ampl)-1 and ivars['mask'] == vars['mask']		# it's a composed rotation
					if ivars[:sh_op] != vars[:sh_op]
						# ensure the rotations are the same orientation
						ivars[:sh_op], ivars[:inv_sh_op] = ivars[:inv_sh_op], ivars[:sh_op]
						ivars['amt'],  ivars['inv_amt']  = ivars['inv_amt'],  ivars['amt']
					end
					amt = Expression[[vars['amt'], :+, ivars['amt']], :%, ampl]
					invamt = Expression[[vars['inv_amt'], :+, ivars['inv_amt']], :%, ampl]
					Expression[[[ivars['var'], vars[:sh_op], amt], :|, [ivars['var'], vars[:inv_sh_op], invamt]], :&, vars['mask']].reduce_rec
				end
			end
		elsif @op == :|
			if    l == 0; r
			elsif r == 0; l
			elsif l == -1 or r == -1; -1
			elsif l == r; l
			elsif l.kind_of? Integer; Expression[r, @op, l].reduce_rec
			elsif l.kind_of? Expression and l.op == @op; Expression[l.lexpr, @op, [l.rexpr, @op, r]].reduce_rec
			end
		elsif @op == :*
			if    l == 0 or r == 0; 0
			elsif l == 1; r
			elsif r == 1; l
			elsif r.kind_of? Integer; Expression[r, @op, l].reduce_rec
			elsif r.kind_of? Expression and r.op == @op; Expression[[l, @op, r.lexpr], @op, r.rexpr].reduce_rec
			end
		elsif @op == :/
			if r == 0
			elsif r.kind_of? Integer and l.kind_of? Expression and l.op == :+ and l.rexpr.kind_of? Integer and l.rexpr % r == 0
				Expression[[l.lexpr, :/, r], :+, l.rexpr/r].reduce_rec
			elsif r.kind_of? Integer and l.kind_of? Expression and l.op == :* and l.lexpr % r == 0
				Expression[l.lexpr/r, :*, l.rexpr].reduce_rec
			end
		elsif @op == :-
			if l == :unknown or r == :unknown; :unknown
			elsif not l and r.kind_of? Expression and (r.op == :- or r.op == :+)
				if r.op == :- # no lexpr (reduced)
					# -(-x) => x
					r.rexpr
				else # :+ and lexpr (r is reduced)
					# -(a+b) => (-a)+(-b)
					Expression[[:-, r.lexpr], :+, [:-, r.rexpr]].reduce_rec
				end
			elsif l
				# a-b => a+(-b)
				Expression[l, :+, [:-, r]].reduce_rec
			end
		elsif @op == :+
			if l == :unknown or r == :unknown; :unknown
			elsif not l; r	# +x  => x
			elsif r == 0; l	# x+0 => x
			elsif l.kind_of?(::Numeric)
				if r.kind_of? Expression and r.op == :+
					# 1+(x+y) => x+(y+1)
					Expression[r.lexpr, :+, [r.rexpr, :+, l]].reduce_rec
				else
					# 1+a => a+1
					Expression[r, :+, l].reduce_rec
				end
				# (a+b)+foo => a+(b+foo)
			elsif l.kind_of? Expression and l.op == @op; Expression[l.lexpr, @op, [l.rexpr, @op, r]].reduce_rec
			elsif l.kind_of? Expression and r.kind_of? Expression and l.op == :% and r.op == :% and l.rexpr.kind_of?(::Integer) and l.rexpr == r.rexpr
				Expression[[l.lexpr, :+, r.lexpr], :%, l.rexpr].reduce_rec
			else
				# a+(b+(c+(-a))) => b+c+0
				# a+((-a)+(b+c)) => 0+b+c
				neg_l = l.rexpr if l.kind_of? Expression and l.op == :-

				# recursive search & replace -lexpr by 0
				simplifier = lambda { |cur|
					if (neg_l and neg_l == cur) or (cur.kind_of? Expression and cur.op == :- and not cur.lexpr and cur.rexpr == l)
						# -l found
						0
					else
						# recurse
						if cur.kind_of? Expression and cur.op == :+
							if newl = simplifier[cur.lexpr]
								Expression[newl, cur.op, cur.rexpr].reduce_rec
							elsif newr = simplifier[cur.rexpr]
								Expression[cur.lexpr, cur.op, newr].reduce_rec
							end
						end
					end
				}

				simplifier[r]
			end
		end

		ret = case v
		when nil
			# no dup if no new value
			(r == :unknown or l == :unknown) ? :unknown :
			((r == @rexpr and l == @lexpr) ? self : Expression[l, @op, r])
		when Expression
			(v.lexpr == :unknown or v.rexpr == :unknown) ? :unknown : v
		else v
		end
		if @@reduce_lambda and ret.kind_of? ExpressionType and newret = @@reduce_lambda[ret] and newret != ret
			if newret.kind_of? ExpressionType
				ret = newret.reduce_rec
			else
				ret = newret
			end
		end
		ret
	end

	# a pattern-matching method
	# Expression[42, :+, 28].match(Expression['any', :+, 28], 'any') => {'any' => 42}
	# Expression[42, :+, 28].match(Expression['any', :+, 'any'], 'any') => false
	# Expression[42, :+, 42].match(Expression['any', :+, 'any'], 'any') => {'any' => 42}
	# vars can match anything except nil
	def match(target, *vars)
		match_rec(target, vars.inject({}) { |h, v| h.update v => nil })
	end

	def match_rec(target, vars)
		return false if not target.kind_of? Expression
		[target.lexpr, target.op, target.rexpr].zip([@lexpr, @op, @rexpr]) { |targ, exp|
			if targ and vars[targ]
				return false if exp != vars[targ]
			elsif targ and vars.has_key? targ
				return false if not vars[targ] = exp
			elsif targ.kind_of? ExpressionType
				return false if not exp.kind_of? ExpressionType or not exp.match_rec(targ, vars)
			else
				return false if targ != exp
			end
		}
		vars
	end

	# returns the array of non-numeric members of the expression
	# if a variables appears 3 times, it will be present 3 times in the returned array
	def externals
		[@rexpr, @lexpr].inject([]) { |a, e|
			case e
			when ExpressionType; a.concat e.externals
			when nil, ::Numeric; a
			else a << e
			end
		}
	end

	# returns the externals that appears in the expression, does not walk through other ExpressionType
	def expr_externals
		[@rexpr, @lexpr].inject([]) { |a, e|
			case e
			when Expression; a.concat e.expr_externals
			when nil, ::Numeric, ExpressionType; a
			else a << e
			end
		}
	end

	def inspect
		"Expression[#{@lexpr.inspect.sub(/^Expression/, '') + ', ' if @lexpr}#{@op.inspect + ', ' if @lexpr or @op != :+}#{@rexpr.inspect.sub(/^Expression/, '')}]"
	end

	Unknown = self[:unknown]
end

# an EncodedData relocation, specifies a value to patch in
class Relocation
	# the relocation value (an Expression)
	attr_accessor :target
	# the relocation expression type
	attr_accessor :type
	# the endianness of the relocation
	attr_accessor :endianness

	include Backtrace

	def initialize(target, type, endianness, backtrace = nil)
		raise ArgumentError, "bad args #{[target, type, endianness].inspect}" if not target.kind_of? Expression or not type.kind_of? ::Symbol or not endianness.kind_of? ::Symbol
		@target, @type, @endianness, @backtrace = target, type, endianness, backtrace
	end

	# fixup the encodeddata with value (reloc starts at off)
	def fixup(edata, off, value)
		str = Expression.encode_imm(value, @type, @endianness, @backtrace)
		edata.fill off
		edata.data[off, str.length] = str
	end

	# size of the relocation field, in bytes
	def length
		Expression::INT_SIZE[@type]/8
	end
end

# a String-like, with export/relocation informations added
class EncodedData
	# string with raw data
	attr_accessor :data
	# hash, key = offset within data, value = +Relocation+
	attr_accessor :reloc
	# hash, key = export name, value = offset within data - use add_export to update
	attr_accessor :export
	# hash, key = offset, value = 1st export name
	attr_accessor :inv_export
	# virtual size of data (all 0 by default, see +fill+)
	attr_accessor :virtsize
	# arbitrary pointer, often used when decoding immediates
	# may be initialized with an export value
	attr_reader   :ptr	# custom writer
	def ptr=(p) @ptr = @export[p] || p end

	# opts' keys in :reloc, :export, :virtsize, defaults to empty/empty/data.length
	def initialize(data = '', opts={})
		@data     = data
		@reloc    = opts[:reloc]    || {}
		@export   = opts[:export]   || {}
		@inv_export = @export.invert
		@virtsize = opts[:virtsize] || @data.length
		@ptr = 0
	end

	def add_export(label, off=@ptr, set_inv=false)
		@export[label] = off
		if set_inv or not @inv_export[off]
			@inv_export[off] = label
		end
	end

	# returns the size of raw data, that is [data.length, last relocation end].max
	def rawsize
		[@data.length, *@reloc.map { |off, rel| off + rel.length } ].max
	end
	# String-like
	alias length virtsize
	# String-like
	alias size virtsize

	def empty?
		@virtsize == 0
	end

	# returns a copy of itself, with reloc/export duped (but not deep)
	def dup
		self.class.new @data.dup, :reloc => @reloc.dup, :export => @export.dup, :virtsize => @virtsize
	end

	# resolve relocations:
	# calculate each reloc target using Expression#bind(binding)
	# if numeric, replace the raw data with the encoding of this value (+fill+s preceding data if needed) and remove the reloc
	# if replace_target is true, the reloc target is replaced with its bound counterpart
	def fixup_choice(binding, replace_target)
		@reloc.keys.each { |off|
			val = @reloc[off].target.bind(binding).reduce
			if val.kind_of? Integer
				reloc = @reloc[off]
				reloc.fixup(self, off, val)
				@reloc.delete(off)	# delete only if not overflowed
			elsif replace_target
				@reloc[off].target = val
			end
		}
	end

	# +fixup_choice+ binding, false
	def fixup(binding)
		fixup_choice(binding, false)
	end

	# +fixup_choice+ binding, true
	def fixup!(binding)
		fixup_choice(binding, true)
	end

	# returns a default binding suitable for use in +fixup+
	# every export is expressed as base + offset
	# base defaults to the first export name + its offset
	def binding(base = nil)
		if not base
			key = @export.keys.sort_by { |k| @export[k] }.first
			return {} if not key
			base = (@export[key] == 0 ? key : Expression[key, :-, @export[key]])
		end
		@export.inject({}) { |binding, (n, o)| binding.update n => Expression[base, :+, o] }
	end

	# returns an array of variables that needs to be defined for a complete #fixup
	# ie the list of externals for all relocations
	def reloc_externals
		@reloc.values.map { |r| r.target.externals }.flatten.uniq - @export.keys
	end

	# returns the offset where the relocation for target t is to be applied
	def offset_of_reloc(t)
		t = Expression[t]
		@reloc.keys.find { |off| @reloc[off].target == t }
	end

	# fill virtual space by repeating pattern (String) up to len
	# expand self if len is larger than self.virtsize
	def fill(len = @virtsize, pattern = 0.chr)
		@virtsize = len if len > @virtsize
		@data = @data.to_str.ljust(len, pattern) if len > @data.length
	end

	# rounds up virtsize to next multiple of len
	def align(len)
		@virtsize = EncodedData.align_size(@virtsize, len)
	end

	# returns the value val rounded up to next multiple of len
	def self.align_size(val, len)
		((val + len - 1) / len).to_i * len
	end

	# concatenation of another +EncodedData+ (or nil/Fixnum/anything supporting String#<<)
	def << other
	
		
		case other
		when nil
		when ::Fixnum
			fill
			@data = @data.realstring if defined? VirtualString and @data.kind_of? VirtualString
			@data << other
			@virtsize += 1
		when EncodedData
			fill if not other.data.empty?
			other.reloc.each  { |k, v| @reloc[k + @virtsize] = v  }
			cf = (other.export.keys & @export.keys).find_all { |k| other.export[k] != @export[k] - @virtsize }
			raise "edata merge: label conflict #{cf.inspect}" if not cf.empty?
			other.export.each { |k, v| @export[k] = v + @virtsize }
			other.inv_export.each { |k, v| @inv_export[@virtsize + k] = v }
			if @data.empty?; @data = other.data.dup
			elsif defined? VirtualString and @data.kind_of? VirtualString; @data = @data.realstring << other.data
			else
				if(other.data.respond_to?('force_encoding'))
					other.data.force_encoding("binary")
				end
				
				@data << other.data
			end
			@virtsize += other.virtsize
		else
			fill
			if @data.empty?; @data = other.dup
			elsif defined? VirtualString and @data.kind_of? VirtualString; @data = @data.realstring << other
			else @data << other
			end
			@virtsize += other.length
		end

		self
	end

	# equivalent to dup << other, filters out Integers & nil
	def + other
		raise ArgumentError if not other or other.kind_of?(Integer)
		dup << other
	end

	# slice
	def [](from, len=nil)
		if not len and from.kind_of? Range
			b = from.begin
			e = from.end
			b = @export[b] if @export[b]
			e = @export[e] if @export[e]
			b = b + @virtsize if b < 0
			e = e + @virtsize if e < 0
			len = e - b
			len += 1 if not from.exclude_end?
			from = b
		end
		from = @export[from] if @export[from]
		from = from + @virtsize if from < 0
		return if from > @virtsize or from < 0

		return @data[from] if not len
		len = @virtsize - from if from+len > @virtsize
		ret = EncodedData.new @data[from, len]
		ret.virtsize = len
		@reloc.each { |o, r|
			ret.reloc[o - from] = r if o >= from and o + r.length <= from+len
		}
		@export.each { |e_, o|
			ret.export[e_] = o - from if o >= from and o <= from+len		# XXX include end ?
		}
		@inv_export.each { |o, e_|
			ret.inv_export[o-from] = e_ if o >= from and o <= from+len
		}
		ret
	end

	# slice replacement, supports size change (shifts following relocs/exports)
	# discards old exports/relocs from the overwritten space
	def []=(from, len, val=nil)
		if not val
			val = len
			len = nil
		end
		if not len and from.kind_of? ::Range
			b = from.begin
			e = from.end
			b = @export[b] if @export[b]
			e = @export[e] if @export[e]
			b = b + @virtsize if b < 0
			e = e + @virtsize if e < 0
			len = e - b
			len += 1 if not from.exclude_end?
			from = b
		end
		from = @export[from] || from
		raise "invalid offset #{from}" if not from.kind_of? ::Integer
		from = from + @virtsize if from < 0

		if not len
			val = val.chr if val.kind_of? ::Integer
			len = val.length
		end
		raise "invalid slice length #{len}" if not len.kind_of? ::Integer or len < 0

		if from >= @virtsize
			len = 0
		elsif from+len > @virtsize
			len = @virtsize-from
		end

		val = EncodedData.new << val

		# remove overwritten metadata
		@export.delete_if { |name, off| off > from and off < from + len }
		@reloc.delete_if { |off, rel| off - rel.length > from and off < from + len }
		# shrink/grow
		if val.length != len
			diff = val.length - len
			@export.keys.each { |name| @export[name] = @export[name] + diff if @export[name] > from }
			@inv_export.keys.each { |off| @inv_export[off+diff] = @inv_export.delete(off) if off > from }
			@reloc.keys.each { |off| @reloc[off + diff] = @reloc.delete(off) if off > from }
			if @virtsize >= from+len
				@virtsize += diff
			end
		end

		@virtsize = from + val.length if @virtsize < from + val.length

		if from + len < @data.length	# patch real data
			val.fill
			@data[from, len] = val.data
		elsif not val.data.empty?	# patch end of real data
			@data << (0.chr*(from-@data.length)) if @data.length < from
			@data[from..-1] = val.data
		else				# patch end of real data with fully virtual
			@data = @data[0, from]
		end
		val.export.each { |name, off| @export[name] = from + off }
		val.inv_export.each { |off, name| @inv_export[from+off] = name }
		val.reloc.each { |off, rel| @reloc[from + off] = rel }
	end

	# replace a portion of self
	# from/to may be Integers (offsets) or labels (from self.export)
	# content is a String or an EncodedData, which will be inserted in the specified location (padded if necessary)
	# raise if the string does not fit in.
	def patch(from, to, content)
		from = @export[from] || from
		raise "invalid offset specification #{from}" if not from.kind_of? Integer
		to = @export[to] || to
		raise "invalid offset specification #{to}" if not to.kind_of? Integer
		raise EncodeError, 'cannot patch data: new content too long' if to - from < content.length
		self[from, content.length] = content
	end
end
end
