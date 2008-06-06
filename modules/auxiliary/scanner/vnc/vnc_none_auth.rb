##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Scanner::Vnc::Vnc_None_Auth < Msf::Auxiliary

	include Exploit::Remote::Tcp
	include Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'VNC Authentication None Detection',
			'Version'     => '$Revision: $',
			'Description' => 'Detect VNC server with empty password.',
			'References'  =>
				[
					['URL', 'http://en.wikipedia.org/wiki/RFB'],
					['URL', 'http://en.wikipedia.org/wiki/Vnc'],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(5900),
		], self.class)
	end

	def run_host(target_host)
		
		connect

		ver = sock.get_once(50,1)
		ver,msg = (ver.split(/\n/))

		# RFB Protocol Version 3.3 (1998-01) 
		# RFB Protocol Version 3.7 (2003-08) 
		# RFB Protocol Version 3.8 (2007-06) 
		if (ver =~ /RFB 003.003|RFB 003.007|RFB 003.008/)

			print_status("#{target_host}:#{rport}, VNC server protocol version : #{ver}")

			if msg

				if (msg =~ /Too many security failures/)
					msg = msg + ". " + "Wait for a moment!"
				end
				print_status("#{target_host}:#{rport}, VNC server warning messages : #{msg}") 

			else	

				# send VNC client protocol version
				cver = ver + "\x0a"
				sock.put(cver)
		
				res = sock.get_once

				# number of security types, security type	
				a,b,c,d = res.unpack("C*")

				# 0 : invalid
				# 1 : none
				# 2 : vnc authentication
				
				if (a and b and c and  d)
					if (a == 0 and b == 0 and c == 0 and d == 2)
						sec_type = "VNC authentication"
					end
					if (a == 0 and b == 0 and c == 0 and d == 0)
						sec_type = "No response. Try again!"
					end
				elsif (a and b)
					if (a == 0 and b == 0)
						sec_type = "Invalid"
					elsif (a == 0 and b == 1 or a == 1 and b == 1)
						sec_type = "None, free access!"
					elsif (a == 0 and b == 2 or a == 1 and b == 2)
						sec_type = "VNC authentication"
					else
						sec_type = "Unknown"
					end
				end

				print_status("#{target_host}:#{rport}, VNC server security types supported : #{sec_type}")
			end
		else
			print_status("#{target_host}:#{rport}, VNC server protocol version : #{ver}, not supported!")
		end

		disconnect
	end
end
end