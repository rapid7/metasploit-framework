module Rex
module Proto
module SMB
module Exceptions


class Error < ::RuntimeError
	
	def initialize(*args)
		super(*args)
		
	end
end

class ReadHeader < Error
	def to_s
		"The SMB response header was invalid"
	end
end

class ReadPacket < Error
	def to_s
		"The SMB response packet was invalid"
	end
end

class WritePacket < Error
	def to_s
		"The SMB packet failed to send"
	end
end

class Unimplemented < Error
	def to_s
		"The SMB packet type was not supported"
	end
end

class NetbiosSessionFailed < Error
	def to_s
		"The server refused our NetBIOS session request"
	end
end

end
end
end
end


