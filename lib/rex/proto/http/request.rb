require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# Request
# -------
#
# HTTP request class.
#
###
class Request < Packet

	##
	#
	# Some individual request types.
	#
	##
	class Get < Request
		def initialize(uri = '/', proto = DefaultProtocol)
			super('GET', uri, proto)
		end
	end

	class Post < Request
		def initialize(uri = '/', proto = DefaultProtocol)
			super('POST', uri, proto)
		end
	end

	class Put < Request
		def initialize(uri = '/', proto = DefaultProtocol)
			super('PUT', uri, proto)
		end
	end

	def initialize(method = 'GET', uri = '/', proto = DefaultProtocol)
		super()

		self.method = method
		self.uri    = uri
		self.proto  = proto
	end

	#
	# Updates the command parts for this specific packet type.
	#
	def update_cmd_parts(str)
		if (md = str.match(/^(.+?)\s+(.+?)\s+HTTP\/(.+?)\r?\n?$/))
			self.method = md[1]
			self.uri    = md[2]
			self.proto  = md[3]
		end
	end

	#
	# Returns the command string derived from the three values
	#
	def cmd_string
		"#{self.method} #{self.uri} HTTP/#{self.proto}\r\n"
	end

	attr_accessor :method
	attr_accessor :uri
	attr_accessor :proto

end

end
end
end
