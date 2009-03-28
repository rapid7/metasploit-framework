##
# $Id$
##

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
	include Msf::Auxiliary::WMAPScanDir
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Interesting File Scanner',
			'Description'	=> %q{
				This module identifies the existence of interesting files 
				in a given directory path.					
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path  to identify files", '/']),
				OptString.new('EXT', [ true, "File extension to use", '.aspx']),
				OptPath.new('DICTIONARY',   [ false, "Path of word dictionary to use", 
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_files.txt")
					]
				)
			], self.class)	
						
	end

	def run_host(ip)
	
		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end 	

		File.open(datastore['DICTIONARY']).each { |testf|
			begin
				testfext = testf.chomp + datastore['EXT']
				res = send_request_cgi({
					'uri'  		=>  tpath+testfext,
					'method'   	=> 'GET',
					'ctype'		=> 'text/plain'
				}, 20)

				if (res and res.code >= 200 and res.code < 300) 
					print_status("Found #{wmap_base_url}#{tpath}#{testfext}")
					
					rep_id = wmap_base_report_id(
						wmap_target_host,
						wmap_target_port,
						wmap_target_ssl
					)
								
					vul_id = wmap_report(rep_id,'FILE','NAME',"#{tpath}#{testfext}","File #{tpath}#{testfext} found.")
					wmap_report(vul_id,'FILE','RESP_CODE',"#{res.code}",nil)
				else
					print_status("NOT Found #{wmap_base_url}#{tpath}#{testfext}") 
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
	
		}
	
	end
end
