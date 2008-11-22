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
			'Name'   		=> 'HTTP Directory Scanner',
			'Description'	=> %q{
				This module identifies the existence of interesting directories 
				in a given directory path.					
			},
			'Author' 		=> [ 'et [at] metasploit.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path  to identify files", '/']),
				OptString.new('ERROR_CODE', [ true, "Error code for non existent directory", '404']),
				OptPath.new('DICTIONARY',   [ false, "Path of word dictionary to use", 
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_dirs.txt")
					]
				),
				OptPath.new('HTTP404S',   [ false, "Path of 404 signatures to use", 
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_404s.txt")
					]
				)				
			], self.class)	
						
	end

	def run_host(ip)
		conn = true
		ecode = nil
		emesg = nil
	
		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end
 	
		ecode = datastore['ERROR_CODE'].to_i
		vhost = datastore['VHOST'] || target_host
		prot  = datastore['SSL'] ? 'https' : 'http'
		
		 
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

			return if not res
			
			tcode = res.code.to_i 

	
			# Look for a string we can signature on as well
			if(tcode >= 200 and tcode <= 299)
			
				File.open(datastore['HTTP404S']).each do |str|
					if(res.body.index(str))
						emesg = str
						break
					end
				end

				if(not emesg)
					print_status("Using first 256 bytes of the response as 404 string")
					emesg = res.body[0,256]
				else
					print_status("Using custom 404 string of '#{emesg}'")
				end
			else
				ecode = tcode
				print_status("Using code '#{ecode}' as not found.")
			end
			
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			conn = false		
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end

		return if not conn
		
	
		File.open(datastore['DICTIONARY']).each do |testf|
			begin
				testfdir = testf.chomp + '/'
				res = send_request_cgi({
					'uri'  		=>  tpath+testfdir,
					'method'   	=> 'GET',
					'ctype'		=> 'text/html'
				}, 20)

				
				if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
					print_status("NOT Found #{prot}://#{vhost}:#{datastore['RPORT']}#{tpath}#{testfdir} #{res.code} (#{target_host})") 					
				else
					print_status("Found #{prot}://#{vhost}:#{datastore['RPORT']}#{tpath}#{testfdir} #{res.code} (#{target_host})")
					rep_id = wmap_base_report_id(
									wmap_target_host,
									wmap_target_port,
									wmap_target_ssl
							)
					vul_id = wmap_report(rep_id,'DIRECTORY','NAME',"#{tpath}#{testfdir}","Directory #{tpath}#{testfdir} found.")
					wmap_report(vul_id,'DIRECTORY','RESP_CODE',"#{res.code}",nil)
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
		end
	
	end
end
