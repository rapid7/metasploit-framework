#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/exe_format/mz'
require 'metasm/exe_format/coff_encode'
require 'metasm/exe_format/coff_decode'

module Metasm
class PE < COFF
	PESIG = "PE\0\0"

	attr_accessor :coff_offset, :signature, :mz

	def initialize(cpu=nil)
		@mz = MZ.new(cpu)
		super(cpu)
	end

	# overrides COFF#decode_header
	# simply sets the offset to the PE pointer before decoding the COFF header
	# also checks the PE signature
	def decode_header
		@encoded.ptr = 0x3c
		@encoded.ptr = decode_word
		@signature = @encoded.read(4)
		raise InvalidExeFormat, "Invalid PE signature #{@signature.inspect}" if @signature != PESIG
		@coff_offset = @encoded.ptr
		if @mz.encoded.empty?
			@mz.encoded << @encoded[0, @coff_offset-4]
			@mz.encoded.ptr = 0
			@mz.decode_header
		end
		super
	end

	# creates a default MZ file to be used in the PE header
	# this one is specially crafted to fit in the 0x3c bytes before the signature
	def encode_default_mz_header
		# XXX use single-quoted source, to avoid ruby interpretation of \r\n
		mzstubp = MZ.assemble(Ia32.new(386, 16), <<'EOMZSTUB')
_str	db "Needs Win32!\r\n$"
start:
	push cs
	pop  ds
	xor  dx, dx	  ; ds:dx = addr of $-terminated string
	mov  ah, 9        ; output string
	int  21h
	mov  ax, 4c01h    ; exit with code in al
	int  21h
EOMZSTUB
		mzparts = @mz.pre_encode

		# put stuff before 0x3c
		@mz.encoded << mzparts.shift
		raise 'OH NOES !!1!!!1!' if @mz.encoded.virtsize > 0x3c	# MZ header is too long, cannot happen
		until mzparts.empty?
			break if mzparts.first.virtsize + @mz.encoded.virtsize > 0x3c
			@mz.encoded << mzparts.shift
		end

		# set PE signature pointer
		@mz.encoded.align 0x3c
		@mz.encoded << encode_word('pesigptr')

		# put last parts of the MZ program
		until mzparts.empty?
			@mz.encoded << mzparts.shift
		end

		# ensure the sig will be 8bytes-aligned
		@mz.encoded.align 8

		@mz.encoded.fixup 'pesigptr' => @mz.encoded.virtsize
		@mz.encoded.fixup @mz.encoded.binding
		@mz.encoded.fill
		@mz.encode_fix_checksum
	end

	# encodes the PE header before the COFF header, uses a default mz header if none defined
	# the MZ header must have 0x3c pointing just past its last byte which should be 8bytes aligned
	# the 2 1st bytes of the MZ header should be 'MZ'
	def encode_header(*a)
		encode_default_mz_header if @mz.encoded.empty?

		@encoded << @mz.encoded.dup

		# append the PE signature
		@signature ||= PESIG
		@encoded << @signature

		super
	end
end

# an instance of a PE file, loaded in memory
# just change the rva_to_off and the section content decoding methods
class LoadedPE < PE
	# just check the bounds / check for 0
	def rva_to_off(rva)
		rva if rva and rva > 0 and rva <= @encoded.virtsize
	end

	# use the virtualaddr/virtualsize fields of the section header
	def decode_sections
		@sections.each { |s|
			s.encoded = @encoded[s.virtaddr, s.virtsize]
		}
	end
end
end
