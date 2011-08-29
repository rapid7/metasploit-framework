module Lab
module Modifier
module Backtrack5

	def nmap(options)
		run_command("nmap #{filter_input(options)}")
	end
	
	def testssl(site)
		run_command("/pentest/scanners/testssl/testssl.sh #{filter_input(site)}")
	end
	
end
end
end

