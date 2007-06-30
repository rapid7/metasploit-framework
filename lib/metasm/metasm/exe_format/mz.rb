#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class MZ < ExeFormat
	class Header
		Fields = [:magic, :cblp, :cp, :crlc, :cparhdr, :minalloc, :maxalloc,
			:ss, :sp, :csum, :ip, :cs, :lfarlc, :ovno]
		attr_accessor(*Fields)

		def encode(mz, relocs)
			h = EncodedData.new
			set_default_values mz, h, relocs
			h << @magic
			Fields[1..-1].each { |m| h << mz.encode_word(send(m)) }
			h.align 16
			h
		end

		def set_default_values mz, h, relocs
			@magic    ||= 'MZ'
			@cblp     ||= Expression[[mz.label_at(mz.body, mz.body.virtsize), :-, mz.label_at(h, 0)], :%, 512]	# number of bytes used in last page
			@cp       ||= Expression[[mz.label_at(mz.body, mz.body.virtsize), :-, mz.label_at(h, 0)], :/, 512]	# number of pages used
			@crlc     ||= relocs.virtsize/4
			@cparhdr  ||= Expression[[mz.label_at(relocs, 0), :-, mz.label_at(h, 0)], :/, 16]	# header size in paragraphs (16o)
			@minalloc ||= ((mz.body.virtsize - mz.body.rawsize) + 15) / 16
			@maxalloc ||= @minalloc
			@ss       ||= 0
			@sp       ||= 0		# ss:sp points at 1st byte of body => works if body does not reach end of segment (or maybe the overflow make the stack go to header space)
			@csum     ||= 0
			@ip       ||= Expression[mz.body.export['start'] || 0]	# when empty relocs, cs:ip looks like an offset from end of header
			@cs       ||= 0
			@lfarlc   ||= Expression[mz.label_at(relocs, 0), :-, mz.label_at(h, 0)]
			@ovno     ||= 0
		end

		def decode(mz)
			@magic = mz.encoded.read 2
			raise InvalidExeFormat, "Invalid MZ signature #{h.magic.inspect}" if @magic != 'MZ'
			Fields[1..-1].each { |m| send("#{m}=", mz.decode_word) }
		end
	end

	class Relocation
		attr_accessor :segment, :offset
		def encode(mz)
			mz.encode_word(@offset) << mz.encode_word(@segment)
		end

		def decode(mz)
			@offset  = mz.decode_word
			@segment = mz.decode_word
		end
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
	def assemble
		@body << assemble_sequence(@source, @cpu)
		@body.fixup @body.binding
		# XXX should create @relocs here
		@source.clear
	end

	# sets up @cursource
	def parse_init
		@cursource = @source
	end

	# encodes the header and the relocation table, return them in an array, with the body.
	def pre_encode
		relocs = @relocs.inject(EncodedData.new) { |edata, r| edata << r.encode(self) }
		header = @header.encode self, relocs
		[header, relocs, @body]
	end

	# concats the header, relocation table and body
	def encode
		pre_encode.inject(@encoded) { |edata, pe| edata << pe }
		@encoded.fixup @encoded.binding
	end

	# returns the raw content of the mz file, with updated checksum
	def encode_string
		super
		encode_fix_checksum
		@encoded.data
	end

	# sets the file checksum (untested)
	def encode_fix_checksum
		@encoded.ptr = 0
		decode_header
		mzlen = @header.cp * 512 + @header.cblp
		@encoded.ptr = 0
		csum = -@header.csum
		(mzlen/2).times { csum += decode_word }
		@encoded[2*Header::Fields.index(:csum), 2] = encode_word(csum)
	end

	# decodes the MZ header from the current offset in self.encoded
	def decode_header
		@header.decode self
	end
	
	# decodes the relocation table
	def decode_relocs
		@relocs.clear
		@encoded.ptr = @header.lfarlc
		@header.crlc.times {
			r = Relocation.new
			r.decode self
			@relocs << r
		}
	end

	# decodes the main part of the program
	# mostly defines the 'start' export, to point to the MZ entrypoint
	def decode_body
		@body = @encoded[@header.cparhdr*16..@header.cp*512+@header.cblp]
		@body.virtsize += @header.minalloc * 16
		@body.export['start'] = @header.cs * 16 + @header.ip
	end

	# returns an MZ object from reading the specified string
	# decodes the header, relocs and body
	def self.decode(str)
		mz = new
		mz.encoded << str
		mz.encoded.ptr = 0
		mz.decode_header
		mz.decode_relocs
		mz.decode_body
		mz
	end
end
end
