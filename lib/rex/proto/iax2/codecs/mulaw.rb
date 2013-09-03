# -*- coding: binary -*-
module Rex
module Proto
module IAX2
module Codecs
class MuLaw < G711


	def self.decode(buff)
		buff.unpack("C*").map{ |x| LOOKUP_ULAW2LIN16[x] }.pack('v*')
	end

end
end
end
end
end
