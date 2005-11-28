require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements input against a socket.
#
###
class Input::Socket < Rex::Ui::Text::Input

	def initialize(sock)
		@sock = sock
	end

	#
	# Sockets do not currently support readline.
	#
	def supports_readline
		false
	end

	#
	# Wait for a line of input to be read from a socket.
	#
	def gets
		return @sock.gets
	end

	#
	# Print a prompt and flush to the socket.
	#
	def _print_prompt(prompt)
		@sock.write(prompt)
		@sock.flush
		prompt
	end

	#
	# Returns whether or not EOF has been reached on stdin.
	#
	def eof?
		@sock.closed?
	end

	#
	# Returns the file descriptor associated with a socket.
	#
	def fd
		return @sock
	end
end

end
end
end
