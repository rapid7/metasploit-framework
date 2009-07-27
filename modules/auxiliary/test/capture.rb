##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
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

			eth = Racket::Ethernet.new(pkt)
			next if not eth.ethertype == 0x0800
					
			ip = Racket::IPv4.new(eth.payload)
			next if not ip.protocol == 6
	
			tcp = Racket::TCP.new(ip.payload)
			next if not (tcp.payload and tcp.payload.length > 0)
			
			if (tcp.payload =~ /GET\s+([^\s]+)\s+HTTP/smi)
				print_status("GET #{$1}")
			end
			
			true
		end
		close_pcap()
		print_status("Finished sniffing")
	end
	
end
