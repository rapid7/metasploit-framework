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

class InvalidPacket < Error
	attr_accessor :word_count
	attr_accessor :command
	attr_accessor :error_code
end

class InvalidWordCount < InvalidPacket
	def to_s
		"The server responded with unimplemented WordCount " + 
		self.word_count.to_s + ' for command ' + self.command.to_s
	end
end

class InvalidCommand < InvalidPacket
	def to_s
		"The server responded with unimplemented command " + 
		self.command.to_s + ' with WordCount ' + self.word_count.to_s
	end
end

class InvalidType < InvalidPacket
	def to_s
		"The server responded with unexpected packet (Command=" + 
		self.command.to_s + ' WordCount=' + self.word_count.to_s + ")"
	end
end

class ErrorCode < InvalidPacket
	def to_s
		"The server responded with error code " + sprintf("0x%.8x", self.error_code) + 
		" (Command=" + self.command.to_s + 
		' WordCount=' + self.word_count.to_s + ")"
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


