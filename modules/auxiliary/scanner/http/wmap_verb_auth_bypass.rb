
##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	
	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Verb Authentication Bypass Scanner',
			'Description'	=> %q{
				This module test for authentication bypass using different HTTP verbs.
					
			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
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
				'WMAP'		
			]

		self.target_port = datastore['RPORT']	

		begin
			res = send_request_raw({
				'uri'          => datastore['PATH'],
				'method'       => 'GET'
			}, 10)

			if res
				rep_id = wmap_base_report_id(
						wmap_target_host,
						wmap_target_port,
						wmap_target_ssl
				)

				auth_code = res.code
				
				if res.headers['WWW-Authenticate']
					print_status("#{ip} requires authentication: #{res.headers['WWW-Authenticate']} [#{auth_code}]")
					wmap_report(rep_id,'WWW-AUTHENTICATE','REALM',"#{res.headers['WWW-Authenticate']}",nil)
					
					verbs.each do |tv|
						resauth = send_request_raw({
							'uri'          => datastore['PATH'],
							'method'       => tv
						}, 10)
						
						if resauth 	
							print_status("Testing verb #{tv} resp code: [#{resauth.code}]")
							if resauth.code != auth_code and resauth.code <= 302
								print_status("Possible authentication bypass with verb #{tv} code #{resauth.code}")
								wmap_report(rep_id,'VULNERABILITY','AUTH_BYPASS_VERB',"#{tv}","Possible auth bypassing with verb #{tv} in #{datastore['PATH']}")
							end
						end
					end	
				else
					print_status("#{ip} No requires authentication. #{datastore['PATH']} #{res.code}")
					
				end
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
