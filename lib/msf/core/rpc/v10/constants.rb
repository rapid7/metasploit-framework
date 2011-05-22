module Msf
module RPC

API_VERSION = "1.0"


class Exception < RuntimeError
	attr_accessor :code, :message
	
	def initialize(code, message)
		self.code    = code
		self.message = message
	end
end



end
end
