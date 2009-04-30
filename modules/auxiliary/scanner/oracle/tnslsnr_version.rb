##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::TNS

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle tnslsnr Service Version Query.',
			'Description'    => %q{
				This module simply queries the tnslsnr service for the Oracle build.
			},
			'Author'         => ['CG'],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 6479 $',
			'DisclosureDate' => 'Jan 7 2009'))

                        register_options([Opt::RPORT(1521),], self.class) 

			deregister_options('RHOST')
	end

	def run_host(ip)
		begin
			connect

			pkt = tns_packet("(CONNECT_DATA=(COMMAND=VERSION))")

			sock.put(pkt)
			
			sleep(0.5)
			
			data = sock.get_once

				if ( data and data =~ /\\*.TNSLSNR for (.*)/ )
					report_note(
						:host	=> ip,
						:proto	=> 'tcp',
						:port	=> datastore['RPORT'],
						:type	=> 'VERSION',
						:data	=> $1
					)
					print_status("Host #{ip} is running: " + $1)
				else
					print_error("Unable to determine version info for #{ip}...")
				end
			disconnect
		rescue ::Rex::ConnectionError
		rescue ::Errno::EPIPE
		end
	end
end
