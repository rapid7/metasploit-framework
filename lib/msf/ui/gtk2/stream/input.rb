module Msf
module Ui
module Gtk2
module Stream

###
#
# This class implements input against Gtk::TextBuffer in.
#
###
class Input < Rex::Ui::Text::Input
	
	def initialize(buffer)
		self.eof = false
		@buffer = buffer
	end
	#
	# Reads text from standard input.
	#
	def sysread(len = 1)
		$stdin.sysread(len)
	end

	#
	# Wait for a line of input to be read from standard input.
	#
	def gets
		return $stdin.gets
	end

	#
	# Print a prompt and flush standard output.
	#
	def _print_prompt(prompt)
		$stdout.print(prompt)
		$stdout.flush
	end

	#
	# Print a prompt and flush standard output.
	#
	def prompt(prompt)
		_print_prompt(prompt)
		return gets()
	end
	
	#
	# Returns whether or not EOF has been reached on stdin.
	#
	def eof?
		$stdin.closed?
	end

	#
	# Returns the file descriptor associated with standard input.
	#
	def fd
		return $stdin
	end
end

end
end
end
end
