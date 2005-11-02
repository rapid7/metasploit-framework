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

	def initialize
		self.buf = ''
	end

	def print(msg = '')
		self.buf += msg || ''

		msg
	end

	def reset
		self.buf = ''
	end
	
	attr_accessor :buf

end

end
end
end
