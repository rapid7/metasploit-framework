require 'msf/base'

module Msf
module Simple

###
#
# Buffer
# ------
#
# Wraps interaction with a generated buffer from the framework.
# Its primary use is to transform a raw buffer into another
# format.
#
###
module Buffer

	#
	# Serializes a buffer to a provided format
	#
	def self.transform(buf, fmt)
		case fmt
			when 'raw'
			when 'ruby'
				buf = Rex::Text.to_ruby(buf)
			when 'perl'
				buf = Rex::Text.to_perl(buf)
			when 'c'
				buf = Rex::Text.to_c(buf)
			else
				raise ArgumentError, "Unsupported buffer format: #{fmt}", caller
		end

		return buf
	end

end

end
end
