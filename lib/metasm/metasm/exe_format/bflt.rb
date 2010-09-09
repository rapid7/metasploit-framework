#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
# BFLT is the binary flat format used by the uClinux
class Bflt < ExeFormat
	MAGIC = 'bFLT'
	FLAGS = { 1 => 'RAM', 2 => 'GOTPIC', 4 => 'GZIP' }

	attr_accessor :header, :text, :data, :reloc, :got

	class Header < SerialStruct
		mem :magic, 4
		words :rev, :entry, :data_start, :data_end, :bss_end, :stack_size,
			:reloc_start, :reloc_count, :flags
		mem :pad, 6*4
		fld_bits(:flags, FLAGS)

		def decode(exe)
			super(exe)

			case @magic
			when MAGIC
			else raise InvalidExeFormat, "Bad bFLT signature #@magic"
			end
		end

		def set_default_values(exe)
			@magic ||= MAGIC
			@rev ||= 4
			@entry ||= 0x40
			@data_start ||= @entry + exe.text.length if exe.text
			@data_end ||= @data_start + exe.data.data.length if exe.data
			@bss_end ||= @data_start + exe.data.length if exe.data
			@stack_size ||= 0x1000
			@reloc_start ||= @data_end
			@reloc_count ||= exe.reloc.length
			@flags ||= []

			super(exe)
		end
	end

	def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end
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

		@encoded.ptr = @header.entry
		@text = EncodedData.new << @encoded.read(@header.data_start - @header.entry)
		@data = EncodedData.new << @encoded.read(@header.data_end - @header.data_start)
		@data.virtsize += (@header.bss_end - @header.data_end)

		if @header.flags.include? 'GZIP'
			# TODO gzip
			raise 'bFLT decoder: gzip format not supported'
		end

		@reloc = []
		@encoded.ptr = @header.reloc_start
		@header.reloc_count.times { @reloc << decode_word }
		if @header.version == 2
			@reloc.map! { |r| r & 0x3fff_ffff }
		end

		decode_interpret_relocs
	end

	def decode_interpret_relocs
		@reloc.each { |r|
			# where the reloc is
			if r >= @header.entry and r < @header.data_start
				section = @text
				base = @header.entry
			elsif r >= @header.data_start and r < @header.data_end
				section = @data
				base = @header.data_start
			else
				puts "out of bounds reloc at #{Expression[r]}" if $VERBOSE
				next
			end

			# what it points to
			section.ptr = r-base
			target = decode_word(section)
			if target >= @header.entry and target < @header.data_start
				target = label_at(@text, target - @header.entry, "xref_#{Expression[target]}")
			elsif target >= @header.data_start and target < @header.bss_end
				target = label_at(@data, target - @header.data_start, "xref_#{Expression[target]}")
			else
				puts "out of bounds reloc target at #{Expression[r]}" if $VERBOSE
				next
			end

			@text.reloc[r-base] = Relocation.new(Expression[target], :u32, @endianness)
		}
	end

	def encode
		create_relocation_table

		# TODO got, gzip
		if @header.flags.include? 'GZIP'
			puts "W: bFLT: clearing gzip flag" if $VERBOSE
			@header.flags.delete 'GZIP'
		end

		@encoded = EncodedData.new
		@encoded << @header.encode(self)
		
		binding = @text.binding(@header.entry).merge(@data.binding(@header.data_start))
		@encoded << @text << @data.data
		@encoded.fixup! binding
		@encoded.reloc.clear

		@relocs.each { |r| @encoded << encode_word(r) }

		@encoded.data
	end

	def create_relocation_table
		@reloc = []
		mapaddr = new_label('mapaddr')
		binding = @text.binding(mapaddr).merge(@data.binding(mapaddr))
		[@text, @data].each { |section|
			base = @header.entry || 0x40
			base = @header.data_start || base+@text.length if section == @data
			section.reloc.each { |o, r|
				if r.endianness == @endianness and [:u32, :a32, :i32].include? r.type and
						Expression[r.target.bind(binding), :-, mapaddr].reduce.kind_of? ::Integer
					@reloc << (base+o)
				else
					puts "bFLT: ignoring unsupported reloc #{r.inspect} at #{Expression[o]}" if $VERBOSE
				end
			}
		}
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
		# entrypoint is the 1st byte of .text
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
		yield @text, @header.entry
		yield @data, @header.data_start
	end
end
end
