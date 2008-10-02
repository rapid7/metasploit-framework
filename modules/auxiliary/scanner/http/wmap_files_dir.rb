##
# $Id: filedir.rb 1000 2008-25-02 08:21:36Z et $
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
			'Version'		=> '$Revision: 1000 $'))   
			
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
					print_status("Found http://#{target_host}:#{datastore['RPORT']}#{tpath}#{testfext}")
				else
					print_status("NOT Found http://#{target_host}:#{datastore['RPORT']}#{tpath}#{testfext}") 
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
	
		}
	
	end
end
	
