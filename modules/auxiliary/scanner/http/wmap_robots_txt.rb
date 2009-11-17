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
			'Version'     => '$Revision$',
			'Description' => 'Detect robots.txt files and analize its content',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)
		
		register_options(
			[
				OptString.new('PATH', [ true,  "The test path to find robots.txt file", '/'])
				
			], self.class)
		
	end

	def run_host(target_host)
	
		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end

		begin
			turl = tpath+'robots.txt'
		
			res = send_request_cgi({
				'uri'          => turl,					
				'method'       => 'GET',
				'version' => '1.0',
			}, 10)

						
			if res and res.body.include?("llow:") 
				print_status("[#{target_host}] #{tpath}robots.txt found")
				
				# short url regex 
				aregex = /llow:[ ]{0,2}(.*?)$/i

				result = res.body.scan(aregex).flatten.map{|s| s.strip}.uniq
				
				print_status("[#{target_host}] #{tpath}robots.txt - #{result.join(", ")}")
				result.each do |u|				
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

