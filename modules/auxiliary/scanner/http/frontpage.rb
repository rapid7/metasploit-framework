##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'FrontPage Server Extensions Detection',
			'Version'     => '$Revision$',
			'Description' => 'Display version information about FPSE.',
			'References'  =>
				[
					['URL', 'http://en.wikipedia.org/wiki/Microsoft_FrontPage'],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		)
	
		register_options(
			[
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request", 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ])
			], self.class)
	end

	def run_host(target_host)
	
		res = send_request_raw({
			'uri'     => '/_vti_inf.html',
			'method'  => 'GET',
			'headers' =>
			{
				'User-Agent' => datastore['UserAgent'],
			}
		}, 20)

		if (res.code >= 200)
			if (res.headers['Server'])
				print_status("http://#{target_host}:#{rport} is running #{res.headers['Server']}")
			end
			if (fpversion = res.body.match(/FPVersion="(.*)"/))
				fpversion = $1
				print_status("FrontPage Version: #{fpversion}")
				if (fpauthor = res.body.match(/FPAuthorScriptUrl="([^"]*)/))
					fpauthor = $1
					print_status("FrontPage Author: http://#{target_host}/#{fpauthor}")
				end
			else
				print_status("FrontPage not found on http://#{target_host}:#{rport} [#{res.code} #{res.message}]")
			end
		end
	end
end

