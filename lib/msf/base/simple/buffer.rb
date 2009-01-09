require 'msf/base'

module Msf
module Simple

###
#
# Wraps interaction with a generated buffer from the framework.
# Its primary use is to transform a raw buffer into another
# format.
#
###
module Buffer

	#
	# Serializes a buffer to a provided format.  The formats supported are raw,
	# ruby, perl, c, js_be, js_le and java
	#
	def self.transform(buf, fmt = "ruby")
		case fmt
			when 'raw'
			when 'ruby'
				buf = Rex::Text.to_ruby(buf)
			when 'perl'
				buf = Rex::Text.to_perl(buf)
			when 'c'
				buf = Rex::Text.to_c(buf)
			when 'js_be'
				buf = Rex::Text.to_unescape(buf, ENDIAN_BIG)
			when 'js_le'
				buf = Rex::Text.to_unescape(buf, ENDIAN_LITTLE)
			when 'java'
				buf = Rex::Text.to_java(buf)
			else
				raise ArgumentError, "Unsupported buffer format: #{fmt}", caller
		end

		return buf
	end

	#
	# Creates a comment using the supplied format.  The formats supported are
	# raw, ruby, perl, js_be, js_le, c, and java.
	#
	def self.comment(buf, fmt = "ruby")
		case fmt
			when 'raw'
			when 'ruby'
				buf = Rex::Text.to_ruby_comment(buf)
			when 'perl'
				buf = Rex::Text.to_perl_comment(buf)
			when 'c'
				buf = Rex::Text.to_c_comment(buf)
			when 'js_be', 'js_le'
				buf = Rex::Text.to_js_comment(buf)
			when 'java'
				buf = Rex::Text.to_c_comment(buf)
			else
				raise ArgumentError, "Unsupported buffer format: #{fmt}", caller
		end

		return buf
	end

end

end
end
