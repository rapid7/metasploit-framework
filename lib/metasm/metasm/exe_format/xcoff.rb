#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class XCoff < ExeFormat
	FLAGS = { 1 => 'RELFLG', 2 => 'EXEC', 4 => 'LNNO', 
		0x200 => 'AR32W', 0x400 => 'PATCH', 0x1000 => 'DYNLOAD',
		0x2000 => 'SHROBJ', 0x4000 => 'LOADONLY' }

	SECTION_FLAGS = { 8 => 'PAD', 0x20 => 'TEXT', 0x40 => 'DATA', 0x80 => 'BSS',
		0x100 => 'EXCEPT', 0x200 => 'INFO', 0x1000 => 'LOADER',
		0x2000 => 'DEBUG', 0x4000 => 'TYPCHK', 0x8000 => 'OVRFLO' }

	attr_accessor :header, :segments, :relocs

	class Header
		attr_accessor :nsec, :timdat, :symptr, :nsym, :opthdr, :flags
		attr_accessor :endianness, :intsize
		def decode(xcoff)
			@endianness, @intsize = case xcoff.encoded.read(2)
			when "\1\xdf": [:big,    32]
			when "\xdf\1": [:little, 32]
			when "\1\xef": [:big,    64]
			when "\xef\1": [:little, 64]
			else raise InvalidExeFormat, "invalid a.out signature"
			end
			@nsec   = xcoff.decode_half
			@timdat = xcoff.decode_word
			@symptr = xcoff.decode_xword
			@nsym   = xcoff.decode_word
			@opthdr = xcoff.decode_half
			@flags  = xcoff.bits_to_hash(xcoff.decode_half, FLAGS)
		end

		def encode(xcoff)
			set_default_values xcoff

			EncodedData.new <<
			xcoff.encode_half(@intsize == 32 ? 0x1df : 0x1ef) <<
			xcoff.encode_half(@nsec) <<
			xcoff.encode_word(@timdat) <<
			xcoff.encode_xword(@symptr) <<
			xcoff.encode_word(@nsym) <<
			xcoff.encode_word(@opthdr) <<
			xcoff.encode_word(xcoff.bits_from_hash(@flags, FLAGS))
		end

		def set_default_values(xcoff)
			@endianness ||= xcoff.cpu ? xcoff.cpu.endianness : :little
			@intsize    ||= xcoff.cpu ? xcoff.cpu.size : 32
			@nsec   ||= xcoff.sections.size
			@timdat ||= 0
			@symptr ||= xcoff.symbols ? xcoff.new_label('symptr') : 0
			@nsym   ||= xcoff.symbols ? xcoff.symbols.length : 0
			@opthdr ||= xcoff.optheader ? OptHeader.size(xcoff) : 0
			@flags  ||= 0
		end
	end

	class OptHeader
		attr_accessor :magic, :vstamp, :tsize, :dsize, :bsize, :entry, :text_start,
			:data_start, :toc, :snentry, :sndata, :sntoc, :snloader, :snbss,
			:algntext, :algndata, :modtype, :cpu, :maxstack, :maxdata, :debugger, :resv

		def self.size(xcoff)
			xcoff.header.intsize == 32 ? 2*2+7*4+10*2+2*4+2+8 : 2*2+7*8+10*2+2*8+2+120
		end

		def decode(xcoff)
			@magic  = xcoff.decode_half
			@vstamp = xcoff.decode_half
			@tsize  = xcoff.decode_xword
			@dsize  = xcoff.decode_xword
			@bsize  = xcoff.decode_xword
			@entry  = xcoff.decode_xword
			@text_start = xcoff.decode_xword
			@data_start = xcoff.decode_xword
			@toc      = xcoff.decode_xword
			@snentry  = xcoff.decode_half
			@sntext   = xcoff.decode_half
			@sndata   = xcoff.decode_half
			@sntoc    = xcoff.decode_half
			@snloader = xcoff.decode_half
			@snbss    = xcoff.decode_half
			@algntext = xcoff.decode_half
			@algndata = xcoff.decode_half
			@modtype  = xcoff.decode_half
			@cpu      = xcoff.decode_half
			@maxstack = xcoff.decode_xword
			@maxdata  = xcoff.decode_xword
			@debugger = xcoff.decode_word
			@res = xcoff.read(xcoff.header.intsize == 32 ? 8 : 120)
		end

		def encode(xcoff)
			set_default_values xcoff
			EncodedData.new <<
			xcoff.encode_half(@magic) <<
			xcoff.encode_half(@vstamp) <<
			xcoff.encode_xword(@tsize) <<
			xcoff.encode_xword(@dsize) <<
			xcoff.encode_xword(@bsize) <<
			xcoff.encode_xword(@entry) <<
			xcoff.encode_xword(@text_start) <<
			xcoff.encode_xword(@data_start) <<
			xcoff.encode_xword(@toc) <<
			xcoff.encode_half(@snentry) <<
			xcoff.encode_half(@sntext) <<
			xcoff.encode_half(@sndata) <<
			xcoff.encode_half(@sntoc) <<
			xcoff.encode_half(@snloader) <<
			xcoff.encode_half(@snbss) <<
			xcoff.encode_half(@algntext) <<
			xcoff.encode_half(@algndata) <<
			xcoff.encode_half(@modtype) <<
			xcoff.encode_half(@cpu) <<
			xcoff.encode_xword(@maxstack) <<
			xcoff.encode_xword(@maxdata) <<
			xcoff.encode_word(@debugger) <<
			@res
		end

		def set_default_values(xcoff)
			@mflags ||= 0
			@vstamp ||= 1
			@tsize ||= 0
			@dsize ||= 0
			@bsize ||= 0
			@entry ||= 0
			@text_start ||= 0
			@data_start ||= 0
			@toc ||= 0
			@snentry ||= 1
			@sntext ||= 1
			@sndata ||= 2
			@sntoc ||= 3
			@snloader ||= 4
			@snbss ||= 5
			@algntext ||= 0
			@algndata ||= 0
			@modtype ||= 0
			@res ||= 0.chr * (xcoff.header.intsize == 32 ? 8 : 120)
		end
	end

	class Section
		attr_accessor :name, :paddr, :vaddr, :size, :scnptr, :relptr, :lnnoptr, :nreloc, :nlnno, :sflags
		attr_accessor :encoded

		def decode(xcoff)
			@name = xcoff.read(8)
			@name = @name[0, @name.index(0)] if @name.index[0]
			@paddr = xcoff.decode_xword
			@vaddr = xcoff.decode_xword
			@size = xcoff.decode_xword
			@scnptr = xcoff.decode_xword
			@relptr = xcoff.decode_xword
			@lnnoptr = xcoff.decode_xword
			xhalf = xcoff.header.intsize == 32 ? 'decode_half' : 'decode_word'
			@nreloc = xcoff.send xhalf
			@nlnno = xcoff.send xhalf
			@flags = xcoff.bits_to_hash(xcoff.send(xhalf), SECTION_FLAGS)
		end

		def encode(xcoff)
			set_default_values xcoff

			n = EncodedData.new << @name
			raise "name #@name too long" if n.virtsize > 8
			n.virtsize = 8

			xhalf = xcoff.header.intsize == 32 ? 'half' : 'word'

			n <<
			xcoff.encode_xword(@paddr) <<
			xcoff.encode_xword(@vaddr) <<
			xcoff.encode_xword(@size) <<
			xcoff.encode_xword(@scnptr) <<
			xcoff.encode_xword(@relptr) <<
			xcoff.encode_xword(@lnnoptr) <<
			xcoff.send("encode_#{xhalf}", @nreloc) <<
			xcoff.send("encode_#{xhalf}", @nlnno) <<
			xcoff.send("encode_#{xhalf}", xcoff.bits_from_hash(@flags, SECTION_FLAGS))
		end

		def set_defalut_values(xcoff)
			@name   ||= @flags.kind_of?(::Array) ? ".#{@flags.first.to_s.downcase}" : ''
			@vaddr  ||= @paddr ? @paddr : @encoded ? xcoff.label_at(@encoded, 0, 's_vaddr') : 0
			@paddr  ||= @vaddr
			@size   ||= @encoded ? @encoded.size : 0
			@scnptr ||= xcoff.new_label('s_scnptr')
			@relptr ||= 0
			@lnnoptr||= 0
			@nreloc ||= 0
			@nlnno  ||= 0
			@flags  ||= 0
		end
	end

	# basic immediates decoding functions
	def decode_half( edata = @encoded) edata.decode_imm(:u16, @header.endianness) end
	def decode_word( edata = @encoded) edata.decode_imm(:u32, @header.endianness) end
	def decode_xword(edata = @encoded) edata.decode_imm((@header.intsize == 32 ? :u32 : :u64), @header.endianness) end
	def encode_half(w)  Expression[w].encode(:u16, @header.endianness) end
	def encode_word(w)  Expression[w].encode(:u32, @header.endianness) end
	def encode_xword(w) Expression[w].encode((@header.intsize == 32 ? :u32 : :u64), @header.endianness) end


	def initialize(cpu=nil)
		@header = Header.new
		@sections = []
		super
	end

	def decode_header(off = 0)
		@encoded.ptr = off
		@header.decode(self)
		if @header.opthdr != 0
			@optheader = OptHeader.new
			@optheader.decode(self)
		end
		@header.nsec.times {
			s = Section.new
			s.decode(self)
			@sections << s
		}
	end

	def decode
		decode_header
		@sections.each { |s|
			s.encoded = @encoded[s.scnptr, s.size]
		}
	end

	def encode
		@encoded = EncodedData.new
		@encoded << @header.encode(self)
		@encoded << @optheader.encode(self) if @optheader
		@sections.each { |s|
			@encoded << s.encode(self)
		}
		va = @encoded.size
		binding = {}
		@sections.each { |s|
			if s.scnptr.kind_of? ::String
				binding[s.scnptr] = @encoded.size
			else
				raise 'scnptr too low' if @encoded.virtsize > s.scnptr
				@encoded.virtsize = s.scnptr
			end
			va = (va + 4096 - 1)/4096*4096
			if s.vaddr.kind_of? ::String
				binding[s.vaddr] = va
			else
				va = s.vaddr
			end
			binding.update s.encoded.binding(va)
			va += s.encoded.size
			@encoded << s.encoded
		}
		@encoded.fixup!(binding)
		@encoded.data
	end
end
end
