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

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'SVN wc.db Scanner',
			'Version'        => '$Revision$',
			'Description'    => %q{
					Scan for servers that allow access to the SVN wc.db file.
					Based on the work by Tim Meddin as described at
					http://pen-testing.sans.org/blog/pen-testing/2012/12/06/all-your-svn-are-belong-to-us#
			},
			'Author'         =>
				[
					'Stephen Haywood <stephen@averagesecurityguy.info',
				],
			'References'     =>
				[
				],
			'License'        =>  MSF_LICENSE
		)

		register_options(
			[
			], self.class)

	end

	def target_url
		if ssl
			return "https://#{vhost}:#{rport}"
		else
			return "http://#{vhost}:#{rport}"
		end
	end

	def run_host(ip)
		if wcdb_exists("#{target_url}")
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
	
	def wcdb_exists(url)

		vprint_status("Trying url: #{url}")
		begin
			res = send_request_cgi(
				{
					'method'  => 'GET',
					'uri'     => '/.svn/wc.db',
					'ctype'   => 'text/plain'
				}, 20)

			if res.code == 200
				return true
			else
				return false
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
