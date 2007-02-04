module Msf
module Ui
module Gtk2
module Stream

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

end
end
end
end
