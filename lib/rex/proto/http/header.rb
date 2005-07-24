require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# Header
# ------
#
# Represents the logical HTTP header portion of an HTTP packet (request or
# response).
#
###
class Packet::Header < Hash

	def initialize
		self.dcase_hash = {}

		reset
	end

	#
	# Parses a header from a string.
	#
	def from_s(header)
		reset

		# Extract the command string
		self.cmd_string = header.slice!(/(.+\r\n)/)

		# Extract each header value pair
		header.split(/\r\n/m).each { |str|
			if (md = str.match(/^(.+?): (.+?)$/))
				self[md[1]] = md[2]
			end
		}
	end

	#
	# More advanced [] that does downcase comparison.
	#
	def [](key)
		begin
			if ((rv = self.fetch(key)) == nil)
				rv = self.dcase_hash[key.downcase]	
			end
		rescue IndexError
			rv = nil
		end

		return rv
	end

	#
	# More advanced []= that does downcase storage.
	#
	def []=(key, value)
		stored = false

		self.each_key { |k|
			if (k.downcase == key.downcase)
				self.store(k, value)
				stored = true
			end
		}

		self.store(key, value) if (stored == false)
		self.dcase_hash[key.downcase] = value
	end

	#
	# Converts the header to a string.
	#
	def to_s(prefix = '')
		str = prefix

		each_pair { |var, val|
			str += "#{var.to_s}: #{val.to_s}\r\n"
		}

		str += "\r\n"

		return str
	end

	#
	# Brings in from an array like yo.
	#
	def from_a(ary)
		ary.each { |e|
			self[e[0]] = e[1]
		}
	end

	#
	# Flushes all header pairs.
	#
	def reset
		self.cmd_string = ''
		self.clear
		self.dcase_hash.clear
	end

	attr_accessor :cmd_string

protected

	attr_accessor :dcase_hash

end

end
end
end
