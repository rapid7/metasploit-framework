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

			eth = Racket::L2::Ethernet.new(pkt)
			next if not eth.ethertype == 0x0800

			ip = Racket::L3::IPv4.new(eth.payload)
			next if not ip.protocol == 6

			tcp = Racket::L4::TCP.new(ip.payload)
			next if !(tcp.payload and tcp.payload.length > 0)

			if (tcp.payload =~ /GET\s+([^\s]+)\s+HTTP/smi)
				url = $1
				print_status("GET #{url}")
				break if url =~ /StopCapture/
			end

		end
		close_pcap()
		print_status("Finished sniffing")
	end

end

