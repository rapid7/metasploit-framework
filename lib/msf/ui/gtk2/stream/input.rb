module Msf
module Ui
module Gtk2
module Stream

class Input < Rex::Ui::Text::Input
	
	def initialize(buffer)
		self.eof = false
		@buffer = buffer
	end
	
	#
	# Whether or not the input medium supports readline.
	#
	def supports_readline
		true
	end

	#
	# Calls the underlying system read.
	#
	def sysread(len)
		raise NotImplementedError
	end

	#
	# Gets a line of input
	#
	def gets
		raise NotImplementedError
	end

	#
	# Has the input medium reached end-of-file?
	#
	def eof?
		return eof
	end

	#
	# Returns a pollable file descriptor that is associated with this
	# input medium.
	#
	def fd
		raise NotImplementedError
	end

	#
	# Indicates whether or not this input medium is intrinsicly a
	# shell provider.  This would indicate whether or not it
	# already expects to have a prompt.
	#
	def intrinsic_shell?
		false
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

	attr_accessor :eof	

end

end
end
end
end
