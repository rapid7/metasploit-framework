module Rex
module Proto
module SMB
module Exceptions


class Error < ::RuntimeError
	@@errors = {}
	def initialize(*args)
		super(*args)
		if @@errors.size == 0
			_load_errors(File.join(File.dirname(__FILE__),'errors.txt'))
		end
	end

	# loads errors.txt
	def _load_errors(file)
		File.open(file).each { |line|
			next if line =~ /^#/
			code, string = line.split
			code = [code].pack('H*').unpack('N')[0]
			@@errors[code] = string
		}
	end

	# returns an error string if it exists, otherwise just the error code
	def get_error (error)
		string = ''
		if @@errors[error]
			string = @@errors[error]
		else
			string = sprintf('0x%.8x',error)
		end
	end
end

class NoReply < Error
	def to_s
		"The SMB server did not reply to our request"
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

class UnknownDialect < Error
	def to_s
		"The server uses an unsupported SMB dialect"
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
		'The server responded with error: ' + 
		self.get_error(self.error_code) +
		" (Command=#{self.command} WordCount=#{self.word_count})"
	end
end

class NetbiosSessionFailed < Error
	def to_s
		"The server refused our NetBIOS session request"
	end
end

class SimpleClientError < Error
	attr_accessor :source, :fatal
end

class LoginError < SimpleClientError
	def to_s
		"Login Failed: " + self.source
	end
end

end
end
end
end


