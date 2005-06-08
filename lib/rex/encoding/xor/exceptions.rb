#!/usr/bin/ruby

module Rex
module Encoding
module Xor

module Exception
	MSG = "Hoe's be frontin n shit"
	def to_s
		self.class::MSG
	end
end

class KeySearchError < ::Exception
	include Exception
	MSG = "Error finding a key."
end

end end end
