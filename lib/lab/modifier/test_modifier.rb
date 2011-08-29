# This assumes you're on a recent ubuntu
# TODO - enforce this, or split it out...

module Lab
module Modifier
module Test
	def dhclient
		run_command("sudo dhclient")
	end
	
	def route
		run_command("route -n")
	end

	def install_nmap
		run_command("sudo apt-get install nmap")
	end

	def nmap(options)
		run_command("nmap #{filter_input(options)}")
	end
end
end
end
