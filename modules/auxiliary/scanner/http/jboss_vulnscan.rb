##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'                  => 'JBoss Vulnerability Scanner',
			'Description'   => %q{
				This module scans a JBoss instance for vulnerablities.
			},
			'Author'                => [ 'Tyler Krpata' ],
			'License'               => BSD_LICENSE
			))

		register_options(
			[
				OptString.new('VERB',  [ true,  "Verb for auth bypass testing", "HEAD"]),
			], self.class)
	end


	def run_host(ip)
		print_status("Processing IP #{ip}")

		res = send_request_cgi({
			'uri'       => "/"+Rex::Text.rand_text_alpha(12),
			'method'    => 'GET',
			'ctype'     => 'text/plain',
		}, 20)
		if (xpb = res.headers['X-Powered-By'])
			print_status("X-Powered-By: #{xpb}")
		end
		if(res.body and />(JBoss[^<]+)/.match(res.body) )
			print_status("JBoss error message: #{$1}")
		end

		apps = [ '/jmx-console/HtmlAdaptor', '/status', '/web-console/ServerInfo.jsp' ]
		apps.each do |app|
			check_app(app)
		end

	end

	def check_app(app)

		res = send_request_cgi({
			'uri'       => app,
			'method'    => 'GET',
			'ctype'     => 'text/plain',
		}, 20)

		if (res)
			case
			when res.code == 200
				print_status("#{app} does not require authentication (200)")
			when res.code == 403
				print_status("#{app} restricted (403)")
			when res.code == 401
				print_status("#{app} requires authentication (401): #{res.headers['WWW-Authenticate']}")
				bypass_auth(app)
			when res.code == 404
				print_status("#{app} not found (404)")
			when res.code == 301, res.code == 302
				print_status("#{app} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
			else
				print_status("Don't know how to handle response code #{res.code}")
			end
		else
			print_status("#{app} not found")
		end
	end

	def bypass_auth(app)

		print_status("Check for verb tampering (HEAD)")

		res = send_request_raw({
			'uri'       => app,
			'method'    => datastore['VERB'],
			'version'   => '1.0' # 1.1 makes the head request wait on timeout for some reason
		}, 20)
		if (res and res.code == 200)
			print_status("Got authentication bypass via HTTP verb tampering")
		else
			print_status("Could not get authentication bypass via HTTP verb tampering")
		end

		res = send_request_cgi({
			'uri'       => app,
			'method'    => 'GET',
			'ctype'     => 'text/plain',
			'basic_auth' => 'admin:admin'
		}, 20)
		if (res and res.code == 200)
			print_status("Authenticated using admin:admin")
		else
			print_status("Could not guess admin credentials")
		end

	end

end
