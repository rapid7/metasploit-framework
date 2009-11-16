#!/usr/bin/env ruby

module Rex
module Encoding
module Xor

module Exception

end

class KeySearchError < ::Exception
	include Exception
	MSG = "Error finding a key."
end

end end end

