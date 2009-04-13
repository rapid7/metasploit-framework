##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TNS
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle Version Enumeration.',
			'Description'    => %q{
				This module simply queries the TNS listner for the Oracle build.
			},
			'Author'         => ['CG'],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'DisclosureDate' => 'Jan 7 2009'))

                        register_options( 
                                [
                                        Opt::RPORT(1521),
                                ], self.class)

	end

def run_host(ip)

		connect_data = "(CONNECT_DATA=(COMMAND=VERSION))"

		pkt = tns_packet(connect_data)

		begin
			connect
		rescue => e
			print_error("#{e}")
			return false
		end

		sock.put(pkt)
		
		sleep(0.5)

		data = sock.get_once

		if ( data and data =~ /\\*.TNSLSNR for (.*)/ )
			return print_status("Host #{ip} is running: " + $1)
		else
			return print_error("Unable to determine version info for #{ip}...")

		disconnect
		
		end
	end
end
