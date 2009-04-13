##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
        
	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	
	def initialize
		super(
			'Name'           => 'EMC AlphaStor Device Manager Service.',
			'Version'        => '$Revision$',
			'Description'    => 'This module querys the remote host for the EMC Alphastor Device Management Service.',
			'Author'         => 'MC',
			'License'        => MSF_LICENSE
		)
		
		register_options([Opt::RPORT(3000),], self.class)
	end


	def run_host(ip)

		connect

		pkt = "\x68" + Rex::Text.rand_text_alphanumeric(5) + "\x00" * 512
		
		sock.put(pkt)

		sleep(0.25)

		data = sock.get_once

		if ( data and data =~ /rrobotd:rrobotd/ )
				print_status("Host #{ip} is running the EMC AlphaStor Device Manager.")
		else
				print_error("Host #{ip} is not running the service...")
		end 

		disconnect

	end
end