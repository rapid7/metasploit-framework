module Msf
module Ui
module Console

class OutputMethod
end

class StdioOutputMethod < OutputMethod
	def print_error(msg)
		print_line("[*] #{msg}")
	end

	def print_status(msg)
		print_line("[-] #{msg}")
	end

	def print_line(msg)
		print(msg + "\n")
	end

	def print(msg)
		$stdout.print(msg)
	end
end

end
end
end
