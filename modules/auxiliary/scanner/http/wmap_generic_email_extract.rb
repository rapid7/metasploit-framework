##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanGeneric
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'WMAP Generic Email Extractor',
			'Description'	=> %q{
				This module extracts email addresses from http responses stored in the wmap database.
			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('DOMAIN', [ false,  "Extract emails from specified domain", ''])
			], self.class)	
							
	end
	
	def wmap_enabled
		false
	end

	def run_host(ip)
		# www.regular-expressions.info/email.html
		emailregex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}/i
		
		#extemails = []
		
		if report_active?
			wmap_request_sql(wmap_target_host,wmap_target_port,'').each do |req|
				result = req.response.scan(emailregex).uniq
				result.each do |addr|
					if addr.include?(datastore['DOMAIN']) and datastore['DOMAIN']
						print_status("Found email #{addr}")
						
						rep_id = wmap_base_report_id(
							wmap_target_host,
							wmap_target_port,
							wmap_target_ssl
						)
						vuln_id = wmap_report(rep_id,'EMAIL','ADDRESS',"#{addr}","Email address found.")
						wmap_report(vuln_id,'LOCATION','PATH',"#{req.path}","Path where email was found.")
					end
				end
			end
		end
	end		
end
