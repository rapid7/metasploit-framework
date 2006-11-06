require 'msf/core'

module Msf

class Auxiliary::TestPcap < Msf::Auxiliary

	include Auxiliary::Report
	include Msf::Exploit::Pcap
	
	def initialize
		super(
			'Name'        => 'Simple Network Capture Tester',
			'Version'     => '$Revision: 3624 $',
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
		pcap_open()
		print_status("Sniffing packets...")
		capture.each_packet do |pkt|
			next if not pkt.tcp?
			next if not pkt.tcp_data
			if (pkt.tcp_data =~ /^GET\s+([^\s]+)\s+HTTP/)
				print_status("GET #{$1}")
			end
		end
	end
	
end

end
