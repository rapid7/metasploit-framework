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
			'Name'           => 'SID Enumeration.',
			'Description'    => %q{
				This module simply queries the TNS listner for the Oracle SID. 
				With Oracle 9.2.0.8 and above the listener will be protected and 
				the SID will have to be bruteforced or guessed.
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

			pkt = tns_packet("(CONNECT_DATA=(COMMAND=STATUS))")

			sock.put(pkt)
			
			sleep(0.5)

			data = sock.get_once

				if ( data and data =~ /ERROR_STACK/ )
					print_error("TNS listener protected for #{ip}...")
				else
					sid = data.scan(/INSTANCE_NAME=([^\)]+)/)
						sid.uniq.each do |s|
							report_note(
								:host   => ip,
								:proto  => 'tcp',
								:port   => datastore['RPORT'],
								:type   => 'INSTANCE_NAME',
								:data   => "#{s}"
							)
							print_status("Identified SID for #{ip}: #{s}")
						end
				end
					service_name = data.scan(/SERVICE_NAME=([^\)]+)/)
						service_name.each do |s|
							report_note(
								:host   => ip,
								:proto  => 'tcp',
								:port   => datastore['RPORT'],
								:type   => 'SERVICE_NAME',
								:data   => "#{s}"
							)
							print_status("Identified SERVICE_NAME for #{ip}: #{s}")
						end
			disconnect
		rescue ::Rex::ConnectionError
		rescue ::Errno::EPIPE
		end
	end
end
