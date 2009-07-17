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

	include Msf::Exploit::Remote::Ip
	include Msf::Auxiliary::Scanner
		
	def initialize
		super(
			'Name'        => 'Simple IP Spoofing Tester',
			'Version'     => '$Revision$',
			'Description' => 'Simple IP Spoofing Tester',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
	end

	def run_host(ip)
		print_status("Sending a packet to host #{ip}")
		
		connect_ip if not ip_sock

		n = Racket::Racket.new

		n.l3 = Racket::IPv4.new
		n.l3.src_ip = ip
		n.l3.dst_ip = ip
		n.l3.protocol = 17
		n.l3.id = 0xdead
		n.l3.ttl = 255
				
		n.l4 = Racket::UDP.new
		n.l4.src_port = 53
		n.l4.dst_port = 53
		n.l4.payload  = "HELLO WORLD"
		
		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip)	
	
		buff = n.pack
		
		ip_sock.sendto(buff, ip)
	end

	
end
