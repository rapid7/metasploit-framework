##
# $Id: repextfile.rb 1000 2008-25-02 08:21:36Z et $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'rex/proto/http'
require 'msf/core'
require 'pathname'



class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanFile
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP File Extension Scanner',
			'Description'	=> %q{
				This module identifies the existence of additional files 
				by modifying the extension of an existing file.
					
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 1000 $'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path/file to identify additional files", '/default.asp']),
				OptString.new('EXT', [ false, "File extension to replace (blank for automatic replacement of extension)", '']), 
			], self.class)	
						
	end

	def run_host(ip)
 		
		extensions= [
					'bak',
 					'txt',
 					'tmp',
 					'old',
 					'temp',
 					'java',
 					'doc',
 					'log'
					]

		tpathfile = Pathname.new(datastore['PATH'])
		tpathnoext = tpathfile.to_s[0..datastore['PATH'].rindex(tpathfile.extname)]
  		

		extensions.each { |testext|
			begin
				tpath = tpathnoext+testext
					res = send_request_cgi({
						'uri'  		=>  tpath,
						'method'   	=> 'GET',
						'ctype'		=> 'text/plain'
				}, 20)

				target_host = datastore['RHOSTS']
				target_port = datastore['RPORT']

				if (res and res.code >= 200 and res.code < 300) 
				   print_status("Found http://#{target_host}:#{target_port}#{tpath}")
				else
				   print_status("NOT Found http://#{target_host}:#{target_port}#{tpath}") 
					#blah
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end	
		}
	
	end

end