##
# $Id: $
##

##
#
# NAT-PMP constants
#
# by Jon Hart <jhart@spoofed.org>
#
##

module Rex
module Proto
module NATPMP

DefaultPort = 5351
Version = 0

	# Protocols that can be mapped
	class ProtocolType
		TCP = 2
		UDP = 1

		def self.to_s(num)
			self.constants.each { |c|
				return c.to_s if self.const_get(c) == num
			}
			'Unknown'
		end
	end
end
end
end
# vim: set ts=4 noet sw=4:
