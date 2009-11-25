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
			'Name'   		=> 'HTTP Previous Directory File Scanner',
			'Description'	=> %q{
				This module identifies files in the first parent directory with same name as
				the given directory path. Example: Test /backup/files/ will look for the
				following files /backup/files.ext .					
			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The test path. The default value will not work.", '/'])
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
			'.jar',
			'.log',
			'.old', 
			'.orig',
			'.o',
			'.tar',
			'.tar.gz',
			'.tgz',
			'.temp',
			'.tmp',
			'.txt',
			'.zip',
			'~'
		]

		tpath = datastore['PATH']
		
		if tpath.eql? "/"||""
			print_error("Blank or default PATH set.");
			return
		end
 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end 
		
		extensions << datastore['EXT']
		
		extensions.each { |ext|
			begin
				testf = tpath.chop+ext

				res = send_request_cgi({
					'uri'  		=>  testf,
					'method'   	=> 'GET',
					'ctype'		=> 'text/plain'
				}, 20)

				if (res and res.code >= 200 and res.code < 300) 
					print_status("Found #{wmap_base_url}#{testf}")
					
					report_note(
						:host	=> target_host,
						:proto	=> 'HTTP',
						:port	=> rport,
						:type	=> 'FILE',
						:data	=> "#{testf} Code: #{res.code}"
					)
					
				else
					print_status("NOT Found #{wmap_base_url}#{testf}") 
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
	
		}
	
	end
end
