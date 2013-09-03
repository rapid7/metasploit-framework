# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

#
# This class serves as the base class for SubStorage, Stream, and Directory head
#
class DirEntry

	attr_accessor :sid
	attr_accessor :_sidChild, :_sidLeftSib, :_sidRightSib

	def initialize(stg)
		@stg = stg

		# default to a root entry :)
		@sid = 0
		@_ab = "Root Entry"
		@_cb = nil              # NOTE: this is not used until pack
		@_mse = STGTY_ROOT
		@_bflags = 0
		@_sidLeftSib = SECT_FREE
		@_sidRightSib = SECT_FREE
		@_sidChild = SECT_FREE
		@_clsId = CLSID.new
		@_dwUserFlags = 0
		@_ctime = "\x00" * 8
		@_mtime = "\x00" * 8
		@_sectStart = SECT_END
		@_ulSize = 0

		# keep track of logical children (in a tree)
		@children = []
	end


	def length
		@_ulSize
	end

	def <<(expr)
		@children << expr
	end

	def each
		@children.each { |de|
			yield de
		}
	end


	def type
		@_mse
	end
	def type=(arg)
		@_mse = arg
	end

	def name
		@_ab
	end
	def name=(arg)
		# XXX: validate?
		@_ab = arg
	end

	def start_sector
		@_sectStart
	end
	def start_sector=(expr)
		@_sectStart = expr
	end


	# NOTE: this will not look at children
	def find_stream_by_name_and_type(name, type)
		@children.each { |de|
			next if (de.type != type)

			if (de.name == name)
				return de
			end
		}
		nil
	end


	def find_by_sid(sid, de=self)
		if (de.sid == sid)
			return de
		end
		@children.each { |cde|
			ret = find_by_sid(cde, sid)
			if (ret)
				return ret
			end
		}
		nil
	end


	#
	# low-level functions
	#
	def from_s(sid, buf)
		@sid = sid
		@_ab           = Util.getUnicodeString(buf[0x00,64])
		@_cb           = Util.get16(buf, 0x40)

		# too big?
		if (@_cb > 0x40)
			raise RuntimeError, 'Invalid directory entry name length %#x' % @_cb
		end

		# mismatch?
		if (@_ab.length > 0)
			declen = ((@_cb) / 2) - 1
			if (declen != @_ab.length)
				raise RuntimeError, 'Directory entry name and length mismatch (%d != %d)' % [declen, @_ab.length]
			end
		end

		@_mse          = Util.get8(buf, 0x42)
		@_bflags       = Util.get8(buf, 0x43)
		@_sidLeftSib   = Util.get32(buf, 0x44)
		@_sidRightSib  = Util.get32(buf, 0x48)
		@_sidChild     = Util.get32(buf, 0x4c)

		# only used for storages..
		@_clsId = CLSID.new(buf[0x50,16])
		@_dwUserFlags  = Util.get32(buf, 0x60)
		@_ctime        = buf[0x64,8]
		@_mtime        = buf[0x6c,8]

		# only used for streams...
		@_sectStart    = Util.get32(buf, 0x74)
		if (@stg.header._uMajorVersion == 4)
			@_ulSize       = Util.get64(buf, 0x78)
		else
			@_ulSize       = Util.get32(buf, 0x78)
		end

		# ignore _dptPropType and pad
	end


	def pack
		@_sectStart ||= SECT_END
		@_cb = (@_ab.length + 1) * 2

		data = ""
		data << Util.putUnicodeString(@_ab) # gets padded/truncated to 0x40 bytes
		data << Util.pack16(@_cb)
		data << Util.pack8(@_mse)
		data << Util.pack8(@_bflags)
		data << Util.pack32(@_sidLeftSib)
		data << Util.pack32(@_sidRightSib)
		data << Util.pack32(@_sidChild)
		data << @_clsId.pack
		data << Util.pack32(@_dwUserFlags)
		data << @_ctime
		data << @_mtime
		data << Util.pack32(@_sectStart)
		data << Util.pack64(@_ulSize)
		data
	end


	def to_s(extra_spaces=0)
		@_sectStart ||= SECT_END
		@_cb = (@_ab.length + 1) * 2

		spstr = " " * extra_spaces

		ret = "%s{\n" % spstr
		ret << "%s  sid => 0x%x" % [spstr, @sid]
		ret << ",\n"
		ret << "%s  _ab => \"%s\"" % [spstr, Util.Printable(@_ab)]
		ret << ",\n"
		ret << "%s  _cb => 0x%04x" % [spstr, @_cb]
		ret << ",\n"
		ret << "%s  _mse => 0x%02x" % [spstr, @_mse]
		ret << ",\n"
		ret << "%s  _bflags => 0x%02x" % [spstr, @_bflags]
		ret << ",\n"
		ret << "%s  _sidLeftSib => 0x%08x" % [spstr, @_sidLeftSib]
		ret << ",\n"
		ret << "%s  _sidRightSib => 0x%08x" % [spstr, @_sidRightSib]
		ret << ",\n"
		ret << "%s  _sidChild => 0x%08x" % [spstr, @_sidChild]
		ret << ",\n"
		ret << "%s  _clsId => %s" % [spstr, @_clsId.to_s]
		ret << ",\n"
		ret << "%s  _dwUserFlags => 0x%08x" % [spstr, @_dwUserFlags]
		ret << ",\n"
		ret << "%s  _ctime => %s" % [spstr, Rex::Text.to_hex_dump(@_ctime).strip]
		ret << "\n"
		ret << "%s  _mtime => %s" % [spstr, Rex::Text.to_hex_dump(@_mtime).strip]
		ret << "\n"
		ret << "%s  _sectStart => 0x%08x" % [spstr, @_sectStart]
		ret << ",\n"
		ret << "%s  _ulSize => 0x%016x" % [spstr, @_ulSize]
		if (@_mse == STGTY_STREAM)
			ret << ",\n"
			ret << "%s  data =>\n" % spstr
			if (@data)
				#ret << Util.Printable(@data)
				ret << Rex::Text.to_hex_dump(@data).strip
			else
				if (@_ulSize > 0)
					ret << "--NOT OPENED YET--"
				end
			end
		elsif (@_mse == STGTY_STORAGE) or (@_mse == STGTY_ROOT)
			if (@children.length > 0)
				ret << ",\n"
				ret << "%s  *children* =>\n" % spstr
				@children.each { |de|
					ret << de.to_s(extra_spaces+2)
					ret << "\n"
				}
			end
		end
		ret << "\n"
		ret << "%s}" % spstr
	end

end

end
end
