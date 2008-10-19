require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements output against a buffer.
#
###
class Output::Buffer < Rex::Ui::Text::Output

	#
	# Initializes an output buffer.
	#
	def initialize
		self.buf = ''
	end

	#
	# Appends the supplied message to the output buffer.
	#
	def print(msg = '')
		self.buf += msg || ''

		if self.on_print_proc
			self.on_print_proc.call(msg)
		end

		msg
	end

	#
	# Reset the buffer to an empty string.
	#
	def reset
		self.buf = ''
	end

	#
	# The underlying buffer state.
	#
	attr_accessor :buf

end

end
end
end