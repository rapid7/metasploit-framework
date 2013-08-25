# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

#
# Should we support major == 4 && sectorshift == 0xc ?
#

module Rex
module OLE

require 'rex/ole/util'

class Header

	attr_accessor :_csectFat, :_sectFat
	attr_accessor :_csectMiniFat, :_sectMiniFatStart
	attr_accessor :_ulMiniSectorCutoff, :_uMiniSectorShift
	attr_accessor :_csectDif, :_sectDifStart
	attr_accessor :_sectDirStart
	attr_accessor :_uMajorVersion

	attr_accessor :sector_size, :idx_per_sect
	attr_accessor :mini_sector_size

	def initialize
		set_defaults

		# calculate some numbers (save a little math)
		@sector_size = 1 << @_uSectorShift
		@mini_sector_size = 1 << @_uMiniSectorShift
		@idx_per_sect = @sector_size / 4
	end

	def set_defaults
		@_abSig               = SIG
		@_clid = CLSID.new
		@_uByteOrder          = LITTLE_ENDIAN

		@_uMinorVersion       = 0x3e
		@_uMajorVersion       = 0x03

		@_uSectorShift        = 9         # 512 byte sectors
		@_uMiniSectorShift    = 6         # 64 byte mini-sectors

		@_csectDir            = nil             # TBD (v4 only, 1 required)

		@_csectFat            = nil             # TBD (one required)
		@_sectDirStart        = nil             # TBD (one required)

		@_signature           = 0               # no transactions support

		@_ulMiniSectorCutoff  = 0x1000    # 4k
		@_sectMiniFatStart    = SECT_END   # TBD
		@_csectMiniFat        = 0               # TBD

		@_sectDifStart        = SECT_END   # TBD (default to none)
		@_csectDif            = 0               # TBD (default to none)

		@_sectFat             = []              # TBD
	end

	def to_s
		ret = "{\n"
		ret << "  _abSig => \"%s\"" % Util.Printable(@_abSig)
		ret << ",\n"
		ret << "  _clid => %s" % @_clid.to_s
		ret << ",\n"
		ret << "  _uMinorVersion => 0x%04x" % @_uMinorVersion
		ret << ",\n"
		ret << "  _uMajorVersion => 0x%04x" % @_uMajorVersion
		ret << ",\n"
		ret << "  _uByteOrder => 0x%04x" % @_uByteOrder
		ret << ",\n"
		ret << "  _uSectorShift => 0x%04x" % @_uSectorShift
		ret << ",\n"
		ret << "  _uMiniSectorShift => 0x%04x" % @_uMiniSectorShift
		ret << ",\n"

		if (@_csectDir)
			ret << "  _csectDir => 0x%08x" % @_csectDir
		else
			ret << "  _csectDir => UNALLOCATED" % @_csectDir
		end
		ret << ",\n"

		if (@_csectFat)
			ret << "  _csectFat => 0x%08x" % @_csectFat
		else
			ret << "  _csectFat => UNALLOCATED"
		end
		ret << ",\n"

		if (@_sectDirStart)
			ret << "  _sectDirStart => 0x%08x" % @_sectDirStart
		else
			ret << "  _sectDirStart => UNALLOCATED"
		end
		ret << ",\n"

		ret << "  _signature => 0x%08x" % @_signature
		ret << ",\n"
		ret << "  _uMiniSectorCutoff => 0x%08x" % @_ulMiniSectorCutoff
		ret << ",\n"
		ret << "  _sectMiniFatStart => 0x%08x" % @_sectMiniFatStart
		ret << ",\n"
		ret << "  _csectMiniFat => 0x%08x" % @_csectMiniFat
		ret << ",\n"
		ret << "  _sectDifStart => 0x%08x" % @_sectDifStart
		ret << ",\n"
		ret << "  _csectDif => 0x%08x" % @_csectDif
		#ret << ",\n"
		#ret << "  _sectFat => "
		#ret << Rex::Text.to_hex_dump32array(@_sectFat)
		ret << "\n}"
		ret
	end

	#
	# low-level functions
	#
	def read(fd)
		buf = fd.read(HDR_SZ)

		@_abSig        = buf[0x00,8]
		if (@_abSig != SIG) and (@_abSig != SIG_BETA)
			raise RuntimeError, 'Invalid signature for OLE file'
		end
		@_clid = CLSID.new(buf[0x08,16])

		@_uByteOrder   = Util.get16(buf, 0x1c)
		Util.set_endian(@_uByteOrder)

		@_uMinorVersion       = Util.get16(buf, 0x18)
		@_uMajorVersion       = Util.get16(buf, 0x1a)

		@_uSectorShift        = Util.get16(buf, 0x1e)
		@_uMiniSectorShift    = Util.get16(buf, 0x20)

		# ignore reserved bytes

		@_csectDir            = Util.get32(buf, 0x28) # NOTE: only for v4 files

		@_csectFat            = Util.get32(buf, 0x2c)
		@_sectDirStart        = Util.get32(buf, 0x30)

		@_signature           = Util.get32(buf, 0x34)

		@_ulMiniSectorCutoff  = Util.get32(buf, 0x38)
		@_sectMiniFatStart    = Util.get32(buf, 0x3c)
		@_csectMiniFat        = Util.get32(buf, 0x40)

		@_sectDifStart        = Util.get32(buf, 0x44)
		@_csectDif            = Util.get32(buf, 0x48)

		@_sectFat = Util.get32array(buf[0x4c, (109 * 4)])
	end

	def write(fd)
		hdr = ""
		hdr << @_abSig
		hdr << @_clid.pack
		hdr << Util.pack16(@_uMinorVersion)
		hdr << Util.pack16(@_uMajorVersion)
		hdr << Util.pack16(@_uByteOrder)
		hdr << Util.pack16(@_uSectorShift)
		hdr << Util.pack16(@_uMiniSectorShift)
		if (@_uMajorVersion == 0x04)
			hdr << "\x00" * 6 # reserved bytes
			hdr << Util.pack32(@_csectDir)
		else
			hdr << "\x00" * 10 # reserved bytes
		end

		fs_count = @_csectFat
		fs_count ||= 0
		hdr << Util.pack32(fs_count)

		dir_start = @_sectDirStart
		dir_start ||= SECT_END
		hdr << Util.pack32(dir_start)

		hdr << Util.pack32(@_signature)
		hdr << Util.pack32(@_ulMiniSectorCutoff)
		hdr << Util.pack32(@_sectMiniFatStart)
		hdr << Util.pack32(@_csectMiniFat)
		hdr << Util.pack32(@_sectDifStart)
		hdr << Util.pack32(@_csectDif)
		hdr << Util.pack32array(@_sectFat)

		fd.seek(0, ::IO::SEEK_SET)
		fd.write(hdr)
	end

end

end
end
