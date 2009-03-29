##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TNS

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle SID Enumeration.',
			'Description'    => %q{
				This module simply queries the TNS listner for the Oracle SID. With 10g Release 2 and above the listener will be protected and the SID will have to be bruteforced or guessed.
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

	def run

		connect_data = "(CONNECT_DATA=(COMMAND=STATUS))"
		pkt = tns_packet(connect_data)

		begin
			connect
		rescue => e
			print_error("#{e}")
			return false
		end

		sock.put(pkt)

		sleep(1)

		data = sock.get_once
		disconnect

		if ( data =~ /ERROR_STACK/ )
			print_error("TNS listener protected for #{rhost}...")

		else

		#sid = data.scan(/INSTANCE_NAME=(\w+)/)
		sid = data.scan(/INSTANCE_NAME=([^\)]+)/)
			sid.uniq.each do |s|
				print_status("Identified SID for #{rhost}: #{s}")
			end

		end 

		#service_name = data.scan(/SERVICE_NAME=(\w+)/)
		service_name = data.scan(/SERVICE_NAME=([^\)]+)/)
			service_name.each do |s|
				print_status("Identified SERVICE_NAME for #{rhost}: #{s}")
			
			end
		end
end
