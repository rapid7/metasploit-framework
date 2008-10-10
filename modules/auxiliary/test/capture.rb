##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Capture
	
	def initialize
		super(
			'Name'        => 'Simple Network Capture Tester',
			'Version'     => '$Revision$',
			'Description' => 'This module sniffs HTTP GET requests from the network',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
				 	[ 'Sniffer' ]
				],
			'PassiveActions' => 
				[
					'Sniffer'
				],
			'DefaultAction'  => 'Sniffer'
		)
	end

	def run
		print_status("Opening the network interface...")
		open_pcap()

		print_status("Sniffing HTTP requests...")
		each_packet() do |pkt|
			next if not pkt.tcp?
			
			if (pkt.payload =~ /GET\s+([^\s]+)\s+HTTP/smi)
				print_status("GET #{$1}")
				p pkt.payload
			end
			
			true
		end
		
		print_status("Finished sniffing")
	end
	
end


