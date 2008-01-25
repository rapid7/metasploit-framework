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

module Msf

class Auxiliary::Test::TestPcap < Msf::Auxiliary

	include Auxiliary::Report
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
		each_packet() do |decoded, pkt|
			data = ''
			
			if(not decoded)
				data = pkt.to_s
			else
				if(pkt.has_layer(Scruby::TCP))
					data = pkt.last_layer.to_net
				end
			end
			
			if (data =~ /GET\s+([^\s]+)\s+HTTP/smi)
				print_status("GET #{$1}")
			end
			
			true
		end
	end
	
end

end
