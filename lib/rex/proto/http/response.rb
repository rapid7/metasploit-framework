require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# Response
# --------
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

	class OK < Response
		def initialize(message = 'OK', proto = DefaultProtocol)
			super(200, message, proto)
		end
	end

	class E404 < Response
		def initialize(message = 'File not found', proto = DefaultProtocol)
			super(404, message, proto)
		end
	end

	#
	# Constructage
	#
	def initialize(code = 200, message = 'OK', proto = DefaultProtocol)
		super()

		self.code    = code.to_i
		self.message = message
		self.proto   = proto

		# Default responses to auto content length on
		self.auto_cl = true
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
