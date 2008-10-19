##
# $Id: vhostscanner.rb 1000 2008-25-02 08:21:36Z et $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'rex/proto/http'
require 'msf/core'

#
# May I reuse some methods?
#
require 'cgi'



	class Metasploit3 < Msf::Auxiliary

		include Msf::Exploit::Remote::HttpClient
		include Msf::Auxiliary::WMAPScanServer
		include Msf::Auxiliary::Scanner


		def initialize(info = {})
			super(update_info(info,	
				'Name'   		=> 'HTTP Virtual Host Brute Force Scanner',
				'Description'	=> %q{
					This module scans a web server for 
					
					},
				'Author' 		=> [ 'et [at] cyberspace.org' ],
				'License'		=> BSD_LICENSE,
				'Version'		=> '$Revision: 1000 $'))   
			
			register_options(
			[
				OptString.new('URI', [ true,  "The URL to use while testing", '/']),
				OptString.new('GET_QUERY', [ false,  "HTTP URI Query", '']),
				OptString.new('DOMAIN', [ true,  "Domain name", '']),
				OptString.new('HEADERS', [ false,  "HTTP Headers", '']),
			], self.class)	
						
		end

		def run_host(ip)	
	
			valstr = [
				"admin",
				"services",
				"webmail",
				"console",
				"apps",
				"mail",
				"intranet",
				"intra",
				"corporate",
				"www",
				"web"
			]
		
			datastore['GET_QUERY'] ? tquery = queryparse(datastore['GET_QUERY']): nil
			datastore['HEADERS'] ? thead = headersparse(datastore['HEADERS']) : nil

			randhost = Rex::Text.rand_text_alpha(5)+"."+datastore['DOMAIN']
		
			begin
				noexistsres = send_request_cgi({
					'uri'  		=>  datastore['URI'],
					'vars_get' 	=>  tquery,
					'headers' 	=>  thead,
					'vhost'		=>  randhost,   
					'method'   	=> 'GET',
					'ctype'		=> 'text/plain'
				}, 20)

				print_status("Sending request with random domain #{randhost} ")
   	
			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
		
			valstr.each do |astr|
				thost = astr+"."+datastore['DOMAIN']
				
				begin
					res = send_request_cgi({
						'uri'  		=>  datastore['URI'],
						'vars_get' 	=>  tquery,
						'headers' 	=>  thead, 
						'vhost'		=>  thost,   
						'method'   	=> 'GET',
						'ctype'		=> 'text/plain'
					}, 20)
			
					if res and noexistsres

						if res.body !=  noexistsres.body 
							print_status("Vhost found  #{thost} ")
						else 
							print_status("NOT Found #{thost}") 
						end
					else
						print_status("NO Response")  	
					end

				rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				rescue ::Timeout::Error, ::Errno::EPIPE			
				end
			
			end
	
		end
	end