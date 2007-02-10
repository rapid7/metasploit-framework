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
	
	def initialize(buffer, entry)
		@buffer = buffer
		@entry = entry
	end
	
	#
	# Reads text from standard input.
	#
	def sysread(len = 1)
		return true
	end

	#
	# Wait for a line of input to be read from standard input.
	#
	def gets
		return @entry.text
	end

	#
	# Print a prompt and flush standard output.
	#
	def _print_prompt(prompt)
		@buffer.insert_at_cursor(prompt)
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
		return true
	end

	#
	# Returns the file descriptor associated with standard input.
	#
	def fd
		a = ::IO.new(0, "w")
		return a
	end
	
end

end
end
end
end
