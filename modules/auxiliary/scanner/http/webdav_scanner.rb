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
			'Name'        => 'HTTP WebDAV Scanner',
			'Version'     => '$Revision$',
			'Description' => 'Detect webservers with WebDAV enabled',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)
		
	end

	def run_host(target_host)

		begin
			res = send_request_raw({
				'uri'          => '/',					
				'method'       => 'OPTIONS'
			}, 10)

			if res and res.code == 200
				
				tserver = res.headers['Server']
				
				if (res.headers['DAV'] == '1, 2') and (res.headers['MS-Author-Via'].match('DAV')) 
					wdtype = 'WEBDAV'
					if res.headers['X-MSDAVEXT']
						wdtype = 'SHAREPOINT DAV'
					end		
					
					print_status("#{target_host} (#{tserver}) has #{wdtype} ENABLED")

					report_note(
					:host	=> target_host,
					:proto	=> 'HTTP',
					:port	=> rport,
					:type	=> wdtype,
					:data	=> 'enabled'
					)

				else
					print_status("#{target_host} (#{tserver}) WebDAV disabled.")
				end
			end	
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

