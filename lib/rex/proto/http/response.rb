require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# HTTP response class.
#
###
class Response < Packet

	##
	#
	# Builtin response class wrappers.
	#
	## 

	#
	# HTTP 200/OK response class wrapper.
	#
	class OK < Response
		def initialize(message = 'OK', proto = DefaultProtocol)
			super(200, message, proto)
		end
	end

	#
	# HTTP 404/File not found response class wrapper.
	#
	class E404 < Response
		def initialize(message = 'File not found', proto = DefaultProtocol)
			super(404, message, proto)
		end
	end

	#
	# Constructage of the HTTP response with the supplied code, message, and
	# protocol.
	#
	def initialize(code = 200, message = 'OK', proto = DefaultProtocol)
		super()

		self.code    = code.to_i
		self.message = message
		self.proto   = proto

		# Default responses to auto content length on
		self.auto_cl = true

		# default chunk sizes (if chunked is used)
		self.chunk_min_size = 1
		self.chunk_max_size = 10
	end

	#
	# Updates the various parts of the HTTP response command string.
	#
	def update_cmd_parts(str)
		if (md = str.match(/HTTP\/(.+?)\s+(\d+)\s?(.+?)\r?\n?$/))
			self.message = md[3].gsub(/\r/, '')
			self.code    = md[2].to_i
			self.proto   = md[1]
		else
			raise RuntimeError, "Invalid response command string", caller
		end
	end

	#
	# Returns the response based command string.
	#
	def cmd_string
		"HTTP\/#{proto} #{code}#{(message and message.length > 0) ? ' ' + message : ''}\r\n"
	end

	attr_accessor :code
	attr_accessor :message
	attr_accessor :proto

end

end
end
end