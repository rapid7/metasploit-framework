##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanDir
	include Msf::Auxiliary::WmapScanFile
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'   		=> 'HTTP Verb Authentication Bypass Scanner',
			'Description'	=> %q{
				This module test for authentication bypass using different HTTP verbs.

			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE))

		register_options(
			[
				OptString.new('PATH', [ true,  "The path to test", '/'])
			], self.class)
	end

	# Fingerprint a single host
	def run_host(ip)

		verbs = [
				'HEAD',
				'TRACE',
				'TRACK',
				'Wmap'
			]


		begin
			res = send_request_raw({
				'uri'          => normalize_uri(datastore['PATH']),
				'method'       => 'GET'
			}, 10)

			if res

				auth_code = res.code

				if res.headers['WWW-Authenticate']
					print_status("#{ip} requires authentication: #{res.headers['WWW-Authenticate']} [#{auth_code}]")

					report_note(
						:host	=> ip,
						:proto => 'tcp',
						:sname => (ssl ? 'https' : 'http'),
						:port	=> rport,
						:type	=> 'WWW_AUTHENTICATE',
						:data	=> "#{datastore['PATH']} Realm: #{res.headers['WWW-Authenticate']}",
						:update => :unique_data
					)

					verbs.each do |tv|
						resauth = send_request_raw({
							'uri'          => normalize_uri(datastore['PATH']),
							'method'       => tv
						}, 10)

						if resauth
							print_status("Testing verb #{tv} resp code: [#{resauth.code}]")
							if resauth.code != auth_code and resauth.code <= 302
								print_status("Possible authentication bypass with verb #{tv} code #{resauth.code}")

								# Unable to use report_web_vuln as method is not in list of allowed methods.

								report_note(
									:host	=> ip,
									:proto => 'tcp',
									:sname => (ssl ? 'https' : 'http'),
									:port	=> rport,
									:type	=> 'AUTH_BYPASS_VERB',
									:data	=> "#{datastore['PATH']} Verb: #{tv}",
									:update => :unique_data
								)

							end
						end
					end
				else
					print_status("[#{ip}] Authentication not required. #{datastore['PATH']} #{res.code}")
				end
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
