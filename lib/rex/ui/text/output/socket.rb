require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements the output interface against a socket.
#
###
class Output::Socket < Rex::Ui::Text::Output

	def initialize(sock)
		@sock = sock
	end

	#
	# Prints the supplied message to the socket.
	#
	def print(msg = '')
		@sock.write(msg)
		@sock.flush

		msg
	end
end

end
end
end