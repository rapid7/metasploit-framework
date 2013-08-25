# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class Util

	def self.Hexify32array(arr)
		ret = ""
		arr.each { |dw|
			ret << " " if ret.length > 0
			ret << "0x%08x" % dw
		}
		ret
	end

	def self.Printable(buf)
		ret = ""
		buf.unpack('C*').each { |byte|
			ch = byte.chr
			if (byte < 0x20 || byte > 0x7e)
				ret << "\\x" + ch.unpack('H*')[0]
			else
				ret << ch
			end
		}
		ret
	end


	def self.set_endian(endian)
		@endian = endian
	end

	def self.get64(buf, offset)
		@endian = LITTLE_ENDIAN if not @endian
		if (@endian == LITTLE_ENDIAN)
			arr = buf[offset,8].unpack('VV')
			return (arr[0] + (arr[1] << 32))
		else
			arr = buf[offset,8].unpack('NN')
			return ((arr[0] << 32) + arr[1])
		end
	end

	def self.pack64(value)
		@endian = LITTLE_ENDIAN if not @endian
		arr = []
		arr << (value & 0xffffffff)
		arr << (value >> 32)
		if (@endian == LITTLE_ENDIAN)
			arr.pack('VV')
		else
			arr.reverse.pack('NN')
		end
	end

	def self.get32(buf, offset)
		@endian = LITTLE_ENDIAN if not @endian
		if (@endian == LITTLE_ENDIAN)
			buf[offset,4].unpack('V')[0]
		else
			buf[offset,4].unpack('N')[0]
		end
	end

	def self.pack32(value)
		@endian = LITTLE_ENDIAN if not @endian
		if (@endian == LITTLE_ENDIAN)
			[value].pack('V')
		else
			[value].pack('N')
		end
	end

	def self.get32array(buf)
		@endian = LITTLE_ENDIAN if not @endian
		if (@endian == LITTLE_ENDIAN)
			buf.unpack('V*')
		else
			buf.unpack('N*')
		end
	end

	def self.pack32array(arr)
		@endian = LITTLE_ENDIAN if not @endian
		if (@endian == LITTLE_ENDIAN)
			arr.pack('V*')
		else
			arr.pack('N*')
		end
	end

	def self.get16(buf, offset)
		@endian = LITTLE_ENDIAN if not @endian
		if (@endian == LITTLE_ENDIAN)
			buf[offset,2].unpack('v')[0]
		else
			buf[offset,2].unpack('n')[0]
		end
	end

	def self.pack16(value)
		@endian = LITTLE_ENDIAN if not @endian
		if (@endian == LITTLE_ENDIAN)
			[value].pack('v')
		else
			[value].pack('n')
		end
	end

	def self.get8(buf, offset)
		buf[offset,1].unpack('C')[0]
	end

	def self.pack8(value)
		[value].pack('C')
	end


	def self.getUnicodeString(buf)
		buf = buf.unpack('S*').pack('C*')
		if (idx = buf.index(0x00.chr))
			buf.slice!(idx, buf.length)
		end
		buf
	end

	def self.putUnicodeString(buf)
		buf = buf.unpack('C*').pack('S*')
		if (buf.length < 0x40)
			buf << "\x00" * (0x40 - buf.length)
		end
		buf
	end


	def self.name_is_valid(name)
		return nil if (name.length > 31)
		(0..0x1f).to_a.each { |x|
			return nil if (name.include?(x.chr))
		}
		return true
	end

end

end
end
