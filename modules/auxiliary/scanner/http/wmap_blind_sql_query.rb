##
# $Id: gvarsparam.rb 1000 2008-25-02 08:21:36Z et $
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
	include Msf::Auxiliary::WMAPScanUniqueQuery
	include Msf::Auxiliary::Scanner


	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Blind SQL Injection GET QUERY Scanner',
			'Description'	=> %q{
				This module identifies the existence of Blind SQL injection issues 
				in GET Query parameters values.
					
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 1000 $'))   
			
		register_options(
			[
				OptString.new('METHOD', [true, "HTTP Method","GET"]),
				OptString.new('PATH', [ true,  "The path/file to test SQL injection", '/index.asp']),
				OptString.new('QUERY', [ true,  "HTTP URI Query", 'p1=v1&p2=v2&p3=v3'])
			], self.class)	
						
	end

	def run_host(ip)
	
		rnum=rand(10000)  
	
		valstr = [
			[ 'numeric', 
			" AND #{rnum}=#{rnum} ",
			" AND #{rnum}=#{rnum+1} "
			], 
			[ 'single quotes', 
			"' AND '#{rnum}'='#{rnum}",
			"' AND '#{rnum}'='#{rnum+1}"
			],
			[ 'double quotes', 
			"\" AND \"#{rnum}\"=\"#{rnum}",
			"\" AND \"#{rnum}\"=\"#{rnum+1}"
			]
		]


		#SEND NORMAL REQUEST 	
   			
		gvars = queryparse(datastore['QUERY']) #Now its a Hash
		
		begin
			normalres = send_request_cgi({
				'uri'  		=>  datastore['PATH'],
				'vars_get' 	=>  gvars,   
				'method'   	=>  datastore['METHOD'],
				'ctype'		=> 'text/plain'
				}, 20)

		
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end
		
		#print_status("Normal request sent.")  		

		valstr.each do |tarr|
   		
			gvars.each do |key,value|		
				gvars = queryparse(datastore['QUERY']) #Now its a Hash
				
				print_status("- Testing '#{tarr[0]}' Parameter #{key}:") 

				#SEND TRUE REQUEST
				gvars[key] = gvars[key]+tarr[1]
   			
				
				begin
					trueres = send_request_cgi({
						'uri'  		=>  datastore['PATH'],
						'vars_get' 	=>  gvars,   
						'method'   	=>  datastore['METHOD'],
						'ctype'		=> 'text/plain'
					}, 20)

				rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				rescue ::Timeout::Error, ::Errno::EPIPE			
				end

				if normalres and trueres
   				
					#Very simple way to compare responses, this can be improved alot , at this time just the simple way 
  				
					reltruesize = trueres.body.length-(trueres.body.scan(/#{tarr[1]}/).length*tarr[1].length) 
					normalsize = normalres.body.length

					#print_status("nlen #{normalsize} reltlen #{reltruesize}")
   				
					if reltruesize == normalsize 					
						#If true it means that we have a small better chance of this being a blind sql injection.

						#SEND FALSE REQUEST
						gvars[key] = gvars[key]+tarr[2]  
   			
				
						begin
							falseres = send_request_cgi({
								'uri'  		=>  datastore['PATH'],
								'vars_get' 	=>  gvars,   
								'method'   	=>  datastore['METHOD'],
								'ctype'		=> 'text/plain'
							}, 20)

							
							if falseres 
  								#Very simple way to compare responses, this can be improved alot , at this time just the simple way 
  								relfalsesize = falseres.body.length-(falseres.body.scan(/#{tarr[2]}/).length*tarr[2].length)
  								#true_false_dist = edit_distance(falseres.body,trueres.body)

  								
  								#print_status("rellenf #{relfalsesize}")

  								if reltruesize > relfalsesize
 									print_status("Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
  								else 
 									print_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}") 
								end
							else
								print_status("NO False Response.")  	
							end

						rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
						rescue ::Timeout::Error, ::Errno::EPIPE			
						end
					else
						print_status("Normal and True requests are different.")
					end
				else
					print_status("No response.")
				end
			end 
		end	
	end
end