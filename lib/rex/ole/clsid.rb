# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##


module Rex
module OLE

class CLSID

	def initialize(buf=nil)
		@buf = buf
		@buf ||= "\x00" * 16
	end

	def pack
		@buf
	end

	def to_s
		ret = ""
		ret << "%08x" % Util.get32(@buf, 0)
		ret << "-"
		ret << "%04x" % Util.get16(@buf, 4)
		ret << "-"
		ret << "%04x" % Util.get16(@buf, 6)
		ret << "-"
		idx = 0
		last8 = @buf[8,8]
		last8.unpack('C*').each { |byte|
			ret << [byte].pack('C').unpack('H*')[0]
			ret << "-" if (idx == 1)
			idx += 1
		}
		ret
	end

end

end
end
