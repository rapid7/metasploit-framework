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
			'Name'   		=> 'HTTP Directory Scanner',
			'Description'	=> %q{
				This module identifies the existence of interesting directories 
				in a given directory path.					
			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 1000 $'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path  to identify files", '/']),
				OptString.new('ERROR_CODE', [ true, "Error code for non existent directory", '404']),
				OptPath.new('DICTIONARY',   [ false, "Path of word dictionary to use", 
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_dirs.txt")
					]
				)
			], self.class)	
						
	end

	def run_host(ip)
		conn = true
	
		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end
 	
		#
		# Detect error code
		# 		
		begin
			randdir = Rex::Text.rand_text_alpha(5).chomp + '/'
			res = send_request_cgi({
				'uri'  		=>  tpath+randdir,
				'method'   	=> 'GET',
				'ctype'		=> 'text/html'
			}, 20)

			if (res)
				ecode = res.code.to_i 
				print_status("Error code set to #{ecode}")
			else
				ecode = datastore['ERROR_CODE']
				print_status("Using default error code #{ecode}")
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			conn = false		
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end
		
		if conn
			File.open(datastore['DICTIONARY']).each { |testf|
				begin
					testfdir = testf.chomp + '/'
					res = send_request_cgi({
						'uri'  		=>  tpath+testfdir,
						'method'   	=> 'GET',
						'ctype'		=> 'text/html'
					}, 20)

					if (res and res.code.to_i != ecode.to_i) 
						print_status("Found http://#{target_host}:#{datastore['RPORT']}#{tpath}#{testfdir}  #{res.code}")
					else
						print_status("NOT Found http://#{target_host}:#{datastore['RPORT']}#{tpath}#{testfdir}  #{res.code}") 
					end

				rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				rescue ::Timeout::Error, ::Errno::EPIPE			
				end
			}
		end
	end
end
