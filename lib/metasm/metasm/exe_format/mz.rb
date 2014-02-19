#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class MZ < ExeFormat
	MAGIC = 'MZ'	# 0x4d5a
	class Header < SerialStruct
		mem :magic, 2, MAGIC
		words :cblp, :cp, :crlc, :cparhdr, :minalloc, :maxalloc, :ss, :sp, :csum, :ip, :cs, :lfarlc, :ovno
		mem :unk, 4

		def encode(mz, relocs)
			h = EncodedData.new
			set_default_values mz, h, relocs
			h << super(mz)
		end

		def set_default_values(mz, h=nil, relocs=nil)
			return if not h
			@cblp     ||= Expression[[mz.label_at(mz.body, mz.body.virtsize), :-, mz.label_at(h, 0)], :%, 512]	# number of bytes used in last page
			@cp       ||= Expression[[mz.label_at(mz.body, mz.body.virtsize), :-, mz.label_at(h, 0)], :/, 512]	# number of pages used
			@crlc     ||= relocs.virtsize/4
			@cparhdr  ||= Expression[[mz.label_at(relocs, 0), :-, mz.label_at(h, 0)], :/, 16]	# header size in paragraphs (16o)
			@minalloc ||= ((mz.body.virtsize - mz.body.rawsize) + 15) / 16
			@maxalloc ||= @minalloc
			@sp       ||= 0		# ss:sp points at 1st byte of body => works if body does not reach end of segment (or maybe the overflow make the stack go to header space)
			@lfarlc   ||= Expression[mz.label_at(relocs, 0), :-, mz.label_at(h, 0)]

			super(mz)
		end

		def decode(mz)
			super(mz)
			raise InvalidExeFormat, "Invalid MZ signature #{h.magic.inspect}" if @magic != MAGIC
		end
	end

	class Relocation < SerialStruct
		words :offset, :segment
	end


	# encodes a word in 16 bits
	def encode_word(val)        Expression[val].encode(:u16, @endianness) end
	# decodes a 16bits word from self.encoded
	def decode_word(edata = @encoded) edata.decode_imm(:u16, @endianness) end


	attr_accessor :endianness, :header, :source
	# the EncodedData representing the content of the file
	attr_accessor :body
	# an array of Relocations - quite obscure
	attr_accessor :relocs

	def initialize(cpu=nil)
		@endianness = cpu ? cpu.endianness : :little
		@relocs = []
		@header = Header.new
		@body = EncodedData.new
		@source = []
		super(cpu)
	end

	# assembles the source in the body, clears the source
	def assemble(*a)
		parse(*a) if not a.empty?
		@body << assemble_sequence(@source, @cpu)
		@body.fixup @body.binding
		# XXX should create @relocs here
		@source.clear
	end

	# sets up @cursource
	def parse_init
		@cursource = @source
		super()
	end

	# encodes the header and the relocation table, return them in an array, with the body.
	def pre_encode
		relocs = @relocs.inject(EncodedData.new) { |edata, r| edata << r.encode(self) }
		header = @header.encode self, relocs
		[header, relocs, @body]
	end

	# defines the exe-specific parser instructions:
	# .entrypoint [<label>]: defines the program entrypoint to label (or create a new label at this location)
	def parse_parser_instruction(instr)
		case instr.raw.downcase
		when '.entrypoint'
			# ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
			@lexer.skip_space
			if tok = @lexer.nexttok and tok.type == :string
				raise instr, 'syntax error' if not entrypoint = Expression.parse(@lexer)
			else
				entrypoint = new_label('entrypoint')
				@cursource << Label.new(entrypoint, instr.backtrace.dup)
			end
			@header.ip = Expression[entrypoint, :-, label_at(@body, 0, 'body')]
			@lexer.skip_space
			raise instr, 'eol expected' if t = @lexer.nexttok and t.type != :eol
		end
	end


	# concats the header, relocation table and body
	def encode
		pre_encode.inject(@encoded) { |edata, pe| edata << pe }
		@encoded.fixup @encoded.binding
		encode_fix_checksum
	end

	# sets the file checksum (untested)
	def encode_fix_checksum
		@encoded.ptr = 0
		decode_header
		mzlen = @header.cp * 512 + @header.cblp
		@encoded.ptr = 0
		csum = -@header.csum
		(mzlen/2).times { csum += decode_word }
		csum &= 0xffff
		@header.csum = csum
		hdr = @header.encode(self, nil)
		@encoded[0, hdr.length] = hdr
	end

	# decodes the MZ header from the current offset in self.encoded
	def decode_header
		@header.decode self
	end

	# decodes the relocation table
	def decode_relocs
		@relocs.clear
		@encoded.ptr = @header.lfarlc
		@header.crlc.times { @relocs << Relocation.decode(self) }
	end

	# decodes the main part of the program
	# mostly defines the 'start' export, to point to the MZ entrypoint
	def decode_body
		@body = @encoded[@header.cparhdr*16...@header.cp*512+@header.cblp]
		@body.virtsize += @header.minalloc * 16
		@body.add_export 'start', @header.cs * 16 + @header.ip
	end

	def decode
		decode_header
		decode_relocs
		decode_body
	end

	def each_section
		yield @body, 0
	end
end
end
