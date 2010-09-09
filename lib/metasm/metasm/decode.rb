#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/render'


module Metasm
# symbolic pointer dereference
# API similar to Expression
class Indirection < ExpressionType
	# Expression (the pointer)
	attr_accessor :target
	alias pointer target
	alias pointer= target=
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

	def hash ; @target.hash^@len.to_i end
	def eql?(o) o.class == self.class and [o.target, o.len] == [@target, @len] end
	alias == eql?

	include Renderable
	def render
		ret = []
		qual = {1 => 'byte', 2 => 'word', 4 => 'dword', 8 => 'qword'}[len] || "_#{len*8}bits" if len
		ret << "#{qual} ptr " if qual
		ret << '[' << @target << ']'
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
			b = @data[ptr-1]
			b = b.unpack('C').first if b.kind_of? ::String	# 1.9
			b
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
		str = str.to_str.ljust(len, "\0") if str.length < len
		@ptr += len
		str
	end

	# decodes an immediate value from self.ptr, advances ptr
	# returns an Expression on relocation, or an ::Integer
	# if ptr has a relocation but the type/endianness does not match, the reloc is ignored and a warning is issued
	# TODO arg type => sign+len
	def decode_imm(type, endianness)
		raise "invalid imm type #{type.inspect}" if not isz = Expression::INT_SIZE[type]
		if rel = @reloc[@ptr]
			if Expression::INT_SIZE[rel.type] == isz and rel.endianness == endianness
				@ptr += rel.length
				return rel.target
			end
			puts "W: Immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect} (wanted #{type.inspect})" if $DEBUG
		end
		Expression.decode_imm(read(isz/8), type, endianness)
	end
	alias decode_immediate decode_imm
end

class Expression
	# decodes an immediate from a raw binary string
	# type may be a length in bytes, interpreted as unsigned, or an expression type (eg :u32)
	# endianness is either an endianness or an object than responds to endianness
	def self.decode_imm(str, type, endianness, off=0)
		type = INT_SIZE.keys.find { |k| k.to_s[0] == ?a and INT_SIZE[k] == 8*type } if type.kind_of? ::Integer
		endianness = endianness.endianness if not endianness.kind_of? ::Symbol
		str = str[off, INT_SIZE[type]/8]
		str = str.reverse if endianness == :little
		val = str.unpack('C*').inject(0) { |val_, b| (val_ << 8) | b }
		val = make_signed(val, INT_SIZE[type]) if type.to_s[0] == ?i
		val
	end
	class << self
		alias decode_immediate decode_imm
	end
end

class CPU
	# decodes the instruction at edata.ptr, mapped at virtual address off
	# returns a DecodedInstruction or nil
	def decode_instruction(edata, addr)
		@bin_lookaside ||= build_bin_lookaside
		di = decode_findopcode edata
		di.address = addr if di
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

	# number of instructions following a jump that are still executed
	def delay_slot(di=nil)
		0
	end
end
end
