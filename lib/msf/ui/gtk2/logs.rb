module Msf
module Ui
module Gtk2
	
class Output < Rex::Ui::Output
	
	def initialize(buffer)
		@buffer = buffer
	end
	
	def print_error(msg = '')
		@buffer.insert_at_cursor("[-] #{msg}\n")
	end
	
	def print_good(msg = '')
		@buffer.insert_at_cursor("[+] #{msg}\n")
	end

	def print_status(msg = '')
		@buffer.insert_at_cursor("[*] #{msg}\n")
	end

	def print_line(msg = '')
		@buffer.insert_at_cursor(msg + "\n")
	end
end

class Input < Rex::Ui::Text::Input
	
	def initialize(buffer)
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
		@buffer.insert_at_cursor(prompt)
		#$stdout.flush
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
