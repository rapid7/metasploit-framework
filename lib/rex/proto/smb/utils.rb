module Rex
module Proto
module SMB
class Utils

require 'rex/text'

	# Convert a standard ASCII string to 16-bit Unicode
	def self.unicode (str)
		str.unpack('C*').pack('v*')
	end
	
	# Convert a name to its NetBIOS equivalent
	def self.nbname_encode (str)
		encoded = ''
		for x in (0..15)
			if (x >= str.length)
				encoded << 'CA'
			else
				c = str[x, 1].upcase[0]
				encoded << [ (c / 16) + 0x41, (c % 16) + 0x41 ].pack('CC')
			end
		end
		return encoded
	end
	
	# Convert a name from its NetBIOS equivalent
	def self.nbname_decode (str)
		decoded = ''
		str << 'A' if str.length % 2 != 0
		while (str.length > 0)
			two = str.slice!(0, 2)
			if (two.length == 2)
				decoded << [ ((two[0] - 0x41) * 16) + two[1] - 0x41 ].pack('C')
			end
		end
		return decoded
	end


end
end
end
end
