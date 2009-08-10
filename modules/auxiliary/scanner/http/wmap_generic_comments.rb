##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanGeneric
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'WMAP Generic Comments Extractor',
			'Description'	=> %q{
				This module extracts commented code from http responses stored in the wmap database.
			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 6479 $'))   
	end
	
	def wmap_enabled
		false
	end

	def run_host(ip)
		hcommregex = /(<!--(.*?)-->|\/\*(.*?)\*\/)/i
		
		
		#extemails = []
		
		if report_active?
			wmap_request_sql(wmap_target_host,wmap_target_port,'').each do |req|
				tpath = req.path
				result = req.response.scan(hcommregex).uniq
				result.each do |c|
					print_status("HTML Comment found #{c} in #{tpath}")
						
					rep_id = wmap_base_report_id(
							wmap_target_host,
							wmap_target_port,
							wmap_target_ssl
					)
					vuln_id = wmap_report(rep_id,'HTML','COMMENT',"#{c}","Comment found in #{tpath}.")
				end
			end
		end
	end		
end
