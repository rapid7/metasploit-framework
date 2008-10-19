require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements text-based output but is not
# tied to an output medium.
#
###
class Output < Rex::Ui::Output

	require 'rex/ui/text/output/stdio'
	require 'rex/ui/text/output/socket'
	require 'rex/ui/text/output/buffer'

	def print_error(msg = '')
		print_line("[-] #{msg}")
	end
	
	def print_good(msg = '')
		print_line("[+] #{msg}")
	end

	def print_status(msg = '')
		print_line("[*] #{msg}")
	end

	def print_line(msg = '')
		print(msg + "\n")
	end

	def reset
	end

end

end
end
end