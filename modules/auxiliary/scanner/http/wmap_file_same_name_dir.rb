
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
	include Msf::Auxiliary::WMAPScanDir
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP File Same Name Directory Scanner',
			'Description'	=> %q{
				This module identifies the existence of files 
				in a given directory path named as the same name of the 
				directory.

				Only works if PATH is differenet than '/'.					
			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The directory path  to identify files", '/']),
				OptString.new('EXT', [ true, "File extension to use", '.aspx'])
				
			], self.class)	
						
	end

	def run_host(ip)
		extensions = [	
			'.null',					
			'.backup',
			'.bak',
			'.c',
			'.class',
			'.copy',
			'.conf',
			'.exe',
			'.html',
			'.htm',
			'.log',
			'.old', 
			'.orig',
			'.tar',
			'.tar.gz',
			'.tgz',
			'.temp',
			'.txt',
			'.zip',
			'~',
			''
		]

		tpath = datastore['PATH']
		
		if tpath.eql? "/"||""
			print_error("Blank or default PATH set.");
			return
		end
 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end 

		testf = tpath.split('/').last

		extensions << datastore['EXT']
		
		extensions.each { |ext|
			begin
				testfext = testf.chomp + ext
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
