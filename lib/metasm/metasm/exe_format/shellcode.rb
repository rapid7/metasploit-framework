#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'

module Metasm
# a shellcode is a simple sequence of instructions
class Shellcode < ExeFormat
	# the array of source elements (Instr/Data etc)
	attr_accessor :source
	# the base address of the shellcode (nil if unspecified)
	attr_accessor :base_addr

	def initialize(cpu=nil, base_addr=nil)
		@base_addr = base_addr
		@source = []
		super(cpu)
	end

	def parse_init
		@cursource = @source
	end

	# allows definition of the base address
	def parse_parser_instruction(instr)
		case instr.raw.downcase
		when '.base_addr'
                        # ".base_addr <expression>"
			# expression should #reduce to integer
			@lexer.skip_space
			raise instr, 'syntax error' if not @base_addr = Expression.parse(@lexer).reduce
			raise instr, 'syntax error' if tok = @lexer.nexttok and tok.type != :eol
		else super
		end
	end

	def get_section_at(addr)
		base = @base_addr || 0
		if not addr.kind_of? Integer
			[@encoded, addr] if @encoded.ptr = @encoded.export[addr]
		elsif addr >= base and addr < base + @encoded.virtsize
			@encoded.ptr = addr - base
			[@encoded, addr]
		end
	end

	def each_section
		yield @encoded, (@base_addr || 0)
	end

	# encodes the source found in self.source
	# appends it to self.encoded
	# clears self.source
	# the optional parameter may contain a binding used to fixup! self.encoded
	# uses self.base_addr if it exists
	def assemble(binding={})
		@encoded << assemble_sequence(@source, @cpu)
		@source.clear
		@encoded.fixup! binding
		@encoded.fixup @encoded.binding(@base_addr)
		@encoded.fill @encoded.rawsize
	end
	alias encode assemble

	# creates a new shellcode from a binary string
	# does not disassemble the instructions
	def self.decode(str, cpu=nil)
		sc = new(cpu)
		sc.encoded << str
		sc
	end

	def self.disassemble(cpu, str, eip=0)
		sc = decode(str, cpu)
		sc.disassemble(eip)
		sc
	end

	alias to_s blocks_to_src
end
end
