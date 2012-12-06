##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'SVN wc.db Scanner',
			'Version'        => '$Revision$',
			'Description'    => %q{
					Scan for servers that allow access to the SVN wc.db file.
					Based on the work by Tim Meddin.	
			},
			'Author'         =>
				[
					'Stephen Haywood <stephen[at]averagesecurityguy.info>',
				],
			'References'     =>
				[
					['URL', 'http://pen-testing.sans.org/blog/pen-testing/2012/12/06/all-your-svn-are-belong-to-us#']
				],
			'License'        =>  MSF_LICENSE
		)

	end

	def target_url(path)
		if ssl
			return "https://#{vhost}:#{rport}#{path}"
		else
			return "http://#{vhost}:#{rport}#{path}"
		end
	end

	def run_host(ip)
		path = '/.svn/wc.db'
		if wcdb_exists(target_url, path)
			print_good("SVN database found on #{target_url}")
			report_note(
				:host => rhost,
				:port => rport,
				:proto => 'tcp',
				:sname => (ssl ? 'https' : 'http'),
				:type => 'users',
				:data => 'SVN wc.db database is available'
			)
		else
			vprint_error("SVN database not found")
		end
	end
	
	def wcdb_exists(url, path)

		vprint_status("Trying #{url}#{path}")
		begin
			res = send_request_cgi(
				{
					'method'  => 'GET',
					'uri'     => path,
					'ctype'   => 'text/plain'
				})

			if res and res.code == 200
				return true
			else
				return false
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
