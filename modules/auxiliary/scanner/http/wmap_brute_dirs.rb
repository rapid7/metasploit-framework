##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'enumerable'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanDir
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Directory Brute Force Scanner',
			'Description'	=> %q{
				This module identifies the existence of interesting directories by brute forcing the name 
				in a given directory path.
					
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path to identify directories", '/']),
				OptInt.new('ERROR_CODE', [ true,  "The expected http code for non existant directories", 404]),
				OptString.new('FORMAT', [ true,  "The expected directory format (a alpha, d digit, A upperalpha, N, n)", 'Aaa'])
			], self.class)	
						
	end

	def wmap_enabled
		true
	end

	def run_host(ip)
	
		numb = []
		datastore['FORMAT'].scan(/./) { |c|
			case c
			when 'a'
				numb << ('a'..'z')
			when 'd'
				numb << ('0'..'9')
			when 'A'
				numb << ('A'..'Z')
			when 'N'
				numb << ('A'..'Z')+('0'..'9')
			when 'n'
				numb << ('a'..'z')+('0'..'9')
			else
				print_status("Format string error")
				return
			end
		} 		

		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end	

		print_status("Using error code #{datastore['ERROR_CODE']}...")
			
		Enumerable.cart(*numb).each {|testd| 
			begin
			  	teststr = tpath+testd.to_s + '/'
				res = send_request_cgi({
					'uri'  		=>  teststr,
					'method'   	=> 'GET',
					'ctype'		=> 'text/plain'
				}, 20)

				if res
					if res.code.to_i != datastore['ERROR_CODE'].to_i
						print_status("Found #{wmap_base_url}#{teststr} #{res.code.to_i}")
									
						rep_id = wmap_base_report_id(
							wmap_target_host,
							wmap_target_port,
							wmap_target_ssl
						)
						wmap_report(rep_id,'DIRECTORY','NAME',"#{teststr}","Directory #{teststr} found.")
									
					else
						print_status("NOT Found #{wmap_base_url}#{teststr}  #{res.code.to_i}") 
						#blah
					end
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
	
		}
	
	end

end
