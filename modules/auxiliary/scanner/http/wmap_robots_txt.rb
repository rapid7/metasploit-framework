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
			'Name'        => 'HTTP Robots.txt Content Scanner',
			'Version'     => '$Revision: 6485 $',
			'Description' => 'Detect robots.txt files and analize its content',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)
		
	end

	def run_host(target_host)

		begin
			res = send_request_cgi({
				'uri'          => '/robots.txt',					
				'method'       => 'GET',
				'version' => '1.0',
			}, 10)

						
			if res and res.body.include?("llow:") 
				# short url regex 
				aregex = /llow:[ ]{0,2}(.*?)$/i

				#print_status("#{res.body}")

				result = res.body.scan(aregex).uniq
				

				result.each do |u|
					print_status("Found file or directory in robot.txt file (#{target_host}) #{u}")
						
					rep_id = wmap_base_report_id(
							wmap_target_host,
							wmap_target_port,
							wmap_target_ssl
						)
					vuln_id = wmap_report(rep_id,'ROBOTS','FILE/DIRECTORY',"#{u}","File/Directory in robots.txt response found.")
				end
			end	
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

