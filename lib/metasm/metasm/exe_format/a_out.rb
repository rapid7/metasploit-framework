#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class AOut < ExeFormat
	MAGIC = { 0407 => 'OMAGIC', 0410 => 'NMAGIC', 0413 => 'ZMAGIC',
		0314 => 'QMAGIC', 0421 => 'CMAGIC'
	}
	MACHINE_TYPE = { 0 => 'OLDSUN2', 1 => '68010', 2 => '68020',
		3 => 'SPARC', 100 => 'PC386', 134 => 'I386', 135 => 'M68K',
		136 => 'M68K4K', 137 => 'NS32532', 138 => 'SPARC',
		139 => 'PMAX', 140 => 'VAX', 141 => 'ALPHA', 142 => 'MIPS',
		143 => 'ARM6', 151 => 'MIPS1', 152 => 'MIPS2', 300 => 'HP300',
		0x20B => 'HPUX800', 0x20C => 'HPUX'
	}
	FLAGS = { 0x10 => 'PIC', 0x20 => 'DYNAMIC' }
	SYMBOL_TYPE = { 0 => 'UNDF', 1 => 'ABS', 2 => 'TEXT',
		3 => 'DATA', 4 => 'BSS', 5 => 'INDR', 6 => 'SIZE',
		9 => 'COMM', 10=> 'SETA', 11=> 'SETT', 12=> 'SETD',
		13=> 'SETB', 14=> 'SETV', 15=> 'FN'
	}

	attr_accessor :endianness, :header, :text, :data, :symbols, :textrel, :datarel

	class Header < SerialStruct
		bitfield :word, 0 => :magic, 16 => :machtype, 24 => :flags
		fld_enum(:magic, MAGIC)
		fld_enum(:machtype, MACHINE_TYPE)
		fld_bits(:flags, FLAGS)
		words :text, :data, :bss, :syms, :entry, :trsz, :drsz

		def decode(aout)
			super(aout)

			case @magic
			when 'OMAGIC', 'NMAGIC', 'ZMAGIC', 'QMAGIC'
			else raise InvalidExeFormat, "Bad A.OUT signature #@magic"
			end
		end

		def set_default_values(aout)
			@magic ||= 'QMAGIC'
			@machtype ||= 'PC386'
			@flags ||= []
			@text ||= aout.text.length + (@magic == 'QMAGIC' ? 32 : 0) if aout.text
			@data ||= aout.data.length if aout.data

			super(aout)
		end
	end

	class Relocation < SerialStruct
		word :address
		bitfield :word, 0 => :symbolnum, 24 => :pcrel, 25 => :length,
 			27 => :extern, 28 => :baserel, 29 => :jmptable, 30 => :relative, 31 => :rtcopy
		fld_enum :length, 0 => 1, 1 => 2, 2 => 4, 3 => 8
		fld_default :length, 4
	end

	class Symbol < SerialStruct
		word :name_p
		bitfield :byte, 0 => :extern, 1 => :type, 5 => :stab
		byte :other
		half :desc
 		word :value
		attr_accessor :name

		def decode(aout, strings=nil)
			super(aout)
			@name = strings[@name_p...(strings.index(?\0, @name_p))] if strings
		end

		def set_default_values(aout, strings=nil)
			if strings and name and @name != ''
				if not @name_p or strings[@name_p, @name.length] != @name
					@name_p = strings.length
					strings << @name << 0
				end
			end
			super(aout, strings)
		end
	end

	def decode_byte(edata = @encoded) edata.decode_imm(:u8 , @endianness) end
	def decode_half(edata = @encoded) edata.decode_imm(:u16, @endianness) end
	def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def encode_byte(w) Expression[w].encode(:u8 , @endianness) end
	def encode_half(w) Expression[w].encode(:u16, @endianness) end
	def encode_word(w) Expression[w].encode(:u32, @endianness) end

	def initialize(cpu = nil)
		@endianness = cpu ? cpu.endianness : :little
		@header = Header.new
		@text = EncodedData.new
		@data = EncodedData.new
		super(cpu)
	end

	def decode_header
		@encoded.ptr = 0
		@header.decode(self)
	end

	def decode
		decode_header

		tlen = @header.text
		case @header.magic
		when 'ZMAGIC'; @encoded.ptr = 1024
		when 'QMAGIC'; tlen -= 32	# header is included in .text
		end
		@text = EncodedData.new << @encoded.read(tlen)

		@data = EncodedData.new << @encoded.read(@header.data)

		textrel = @encoded.read @header.trsz
		datarel = @encoded.read @header.drsz
		syms    = @encoded.read @header.syms
		strings = @encoded.read
		# TODO
	end

	def encode
		# non mmapable on linux anyway
		# could support OMAGIC..
		raise EncodeError, 'cannot encode non-QMAGIC a.out' if @header.magic and @header.magic != 'QMAGIC'

		# data must be 4096-aligned
		# 32 bytes of header included in .text
		@text.virtsize = (@text.virtsize + 32 + 4096 - 1) / 4096 * 4096 - 32
		if @data.rawsize % 4096 != 0
			@data[(@data.rawsize + 4096 - 1) / 4096 * 4096 - 1] = 0
		end

		@header.text = @text.length+32
		@header.data = @data.rawsize
		@header.bss = @data.virtsize - @data.rawsize

		@encoded = EncodedData.new
		@encoded << @header.encode(self)
		binding = @text.binding(4096+32).merge @data.binding(4096 + @header.text)
		@encoded << @text << @data
		@encoded.fixup! binding
		@encoded.data
	end

	def parse_init
		@textsrc ||= []
		@datasrc ||= []
		@cursource ||= @textsrc
		super()
	end

	def parse_parser_instruction(instr)
		case instr.raw.downcase
		when '.text'; @cursource = @textsrc
		when '.data'; @cursource = @datasrc
		when '.entrypoint'
			# ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
			@lexer.skip_space
			if tok = @lexer.nexttok and tok.type == :string
				raise instr if not entrypoint = Expression.parse(@lexer)
			else
				entrypoint = new_label('entrypoint')
				@cursource << Label.new(entrypoint, instr.backtrace.dup)
			end
			@header.entry = entrypoint
		else super(instr)
		end
	end

	def assemble(*a)
		parse(*a) if not a.empty?
		@text << assemble_sequence(@textsrc, @cpu)
		@textsrc.clear
		@data << assemble_sequence(@datasrc, @cpu)
		@datasrc.clear
		self
	end

	def each_section
		tva = 0
		tva = 4096+32 if @header.magic == 'QMAGIC'
		yield @text, tva
		yield @data, tva + @text.virtsize
	end
end
end
