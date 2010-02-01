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
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Directory Listing Scanner',
			'Description'	=> %q{
				This module identifies directory listing vulnerabilities 
				in a given directory path.					
			},
			'Author' 		=> [ 'et' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path to identify directoy listing", '/'])
			], self.class)	
						
	end

	def run_host(ip)
	
		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end 	

		begin
			res = send_request_cgi({
				'uri'  		=>  tpath,
				'method'   	=> 'GET',
				'ctype'		=> 'text/plain'
				}, 20)

			if (res and res.code >= 200 and res.code < 300)
				if res.to_s.include? "<title>Index of /" and res.to_s.include? "<h1>Index of /"
	 				print_status("Found Directory Listing #{wmap_base_url}#{tpath}")
					
					report_note(
						:host	=> ip,
						:proto	=> 'HTTP',
						:port	=> rport,
						:type	=> 'DIR_LISTING',
						:data	=> "#{tpath}"
					)
					
				end

				if res.to_s.include? "[To Parent Directory]</A>" and res.to_s.include? "#{tpath}</H1><hr>"
	 				print_status("Found Directory Listing #{wmap_base_url}#{tpath}")
					
					report_note(
						:host	=> ip,
						:proto	=> 'HTTP',
						:port	=> rport,
						:type	=> 'DIR_LISTING',
						:data	=> "#{tpath}"
					)
					
				end

			else
				print_status("NOT Vulnerable to directory listing #{wmap_base_url}#{tpath}") 
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end
	end
end
