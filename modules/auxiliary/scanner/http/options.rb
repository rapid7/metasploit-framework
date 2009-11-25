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
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP Options Detection',
			'Version'     => '$Revision$',
			'Description' => 'Display available HTTP options for each system',
			'Author'       => ['CG'],
			'License'     => MSF_LICENSE
		)
		
	end

	def run_host(target_host)

		begin
			res = send_request_raw({
				'version'      => '1.0',
				'uri'          => '/',					
				'method'       => 'OPTIONS'
			}, 10)

			if (res and res.headers['Allow'])
				print_status("#{target_host} allows #{res.headers['Allow']} methods")

				report_note(
					:host	=> target_host,
					:proto	=> 'HTTP',
					:port	=> rport,
					:type	=> 'HTTP_OPTIONS',
					:data	=> res.headers['Allow']
				)

			else
				''
			end
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

