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
			'Name'        => 'Simple Ethernet Frame Spoofer',
			'Version'     => '$Revision$',
			'Description' => 'This module sends spoofed ethernet frames',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
				 	[ 'Spoofer' ]
				],
			'DefaultAction'  => 'Spoofer'
		)
	end

	def run
		print_status("Opening the network interface...")
		open_pcap()

		r = Racket::Racket.new
		r.l2 = Racket::Ethernet.new
		r.l2.ethertype = 0x0800
		r.l2.src_mac = "00:41:41:41:41:41"
		r.l2.dst_mac = "00:42:42:42:42:42"
		r.l3 = Racket::IPv4.new
		r.l3.src_ip  = "41.41.41.41"
		r.l3.dst_ip  = "42.42.42.42"
		r.l3.protocol = 17
		r.l4 = Racket::UDP.new
		r.l4.src_port = 0x41
		r.l4.dst_port = 0x42
		r.l4.payload  = "SPOOOOOFED"
		r.l4.fix!(r.l3.src_ip, r.l3.dst_ip)
		
		1.upto(10) do
			capture.inject(r.pack)
		end
		
		close_pcap()
		print_status("Finished sending")
	end
	
end
