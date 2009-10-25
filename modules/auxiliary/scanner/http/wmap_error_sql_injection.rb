##
# $Id: wmap_error_sql_injection.rb 6479 2009-04-13 14:33:26Z kris $
##

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
	include Msf::Auxiliary::WMAPScanUniqueQuery
	include Msf::Auxiliary::Scanner


	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Error Based SQL Injection Scanner',
			'Description'	=> %q{
				This module identifies the existence of Error Based SQL injection issues. Still requires alot of work
					
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 6479 $'))   
			
		register_options(
			[
				OptString.new('METHOD', [ true, "HTTP Method",'GET']),
				OptString.new('PATH', [ true,  "The path/file to test SQL injection", '/default.aspx']),
				OptString.new('QUERY', [ false,  "HTTP URI Query", '']),
				OptString.new('DATA', [ false, "HTTP Body Data", '']),
				OptString.new('COOKIE',[ false, "HTTP Cookies", ''])
			], self.class)	
						
	end

	def run_host(ip)
	
		gvars = nil
		pvars = nil
		cvars = nil
	
	
		sqlinj = [
			[ "'" ,'Single quote'],
			[ "')",'Single quote and parenthesis'],
			[ "\"",'Double quote'] 				
		]
	
		errorstr = [
			[
				"Unclosed quotation mark after the character string",
				'MSSQL',
				'string'
			]
		]
		
		#
		# Dealing with empty query/data and making them hashes.
		#

		if !datastore['QUERY'] or datastore['QUERY'].empty?
			gvars = queryparse(datastore['QUERY']) #Now its a Hash
		else
			gvars = nil
		end
	
		if !datastore['DATA'] or datastore['DATA'].empty?
			datastore['DATA'] = nil
			pvars = nil
		else
			pvars = queryparse(datastore['DATA'])
		end
		
		if !datastore['COOKIE'] or datastore['COOKIE'].empty?
			datastore['COOKIE'] = nil
			cvars = nil
		else
			cvars = queryparse(datastore['COOKIE'])
		end


		#
		# Send normal request to check if error is generated 
		# (means the error is caused by other means)
		#
   		#
					
		begin
			normalres = send_request_cgi({
				'uri'  		=>  datastore['PATH'],
				'vars_get' 	=>  gvars,   
				'method'   	=>  datastore['METHOD'],
				'ctype'		=> 'application/x-www-form-urlencoded',
	            'cookie'    => datastore['COOKIE'],
	            'data'      => datastore['DATA']
				}, 20)

		
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end
		
		print_status("Normal request sent.")  
		
		found = false
		inje = nil
		dbt = nil
		injt = nil
		
		
		if normalres
			errorstr.each do |estr,dbtype,injtype|
				if normalres.body.include? estr
					found = true
					inje = estr
					dbt = dbtype
					injt = injtype					
				end
			end
			
			if found
				print_error("Error string appears in the normal response, unable to test")
				print_error("Error string: '#{inje}'") 
				print_error("DB TYPE: #{dbt}, Error type '#{injt}'")
				
				rep_id = wmap_base_report_id(
						wmap_target_host,
						wmap_target_port,
						wmap_target_ssl
				)
				vul_id = wmap_report(rep_id,'ERROR','ERROR_BASED_SQL_INJECTION',"#{datastore['PATH']}","Unable to test as normal response contains error message without injecting anything parameter")
				wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','ERROR_STRING',"#{inje}","Error message found #{inje}")
				wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','DB_TYPE',"#{dbt}","Database type is #{dbt}")
				
				return
			end
		else
			print_status("No response")
			return																	
		end
		
		#
		# Test URI Query parameters
   		#
		
		found = false
		
		if gvars
			sqlinj.each do |istr,idesc|
			
				if found 
					break 
				end
			
				gvars.each do |key,value|		
					gvars = queryparse(datastore['QUERY']) #Now its a Hash
				
					print_status("- Testing query with #{idesc}. Parameter #{key}:") 
					gvars[key] = gvars[key]+istr
   			
					begin
						testres = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'vars_get' 	=>  gvars,   
							'method'   	=>  datastore['METHOD'],
							'ctype'		=> 'application/x-www-form-urlencoded',
							'cookie'    => datastore['COOKIE'],
							'data'      => datastore['DATA']
						}, 20)
					
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
					rescue ::Timeout::Error, ::Errno::EPIPE			
					end

					if testres 
						errorstr.each do |estr,dbtype,injtype|
							if testres.body.include? estr
								found = true
								inje = estr
								dbt = dbtype
								injt = injtype					
							end
						end
			
						if found
							print_status("SQL Injection found.")
							print_status("Error string: '#{inje}' Test Value: #{istr}") 
							print_status("Vuln query parameter: #{key} DB TYPE: #{dbt}, Error type '#{injt}'")
							
							rep_id = wmap_base_report_id(
									wmap_target_host,
									wmap_target_port,
									wmap_target_ssl
							)
							vul_id = wmap_report(rep_id,'VULNERABILITY','ERROR_BASED_SQL_INJECTION',"#{datastore['PATH']}","SQL Injection found (Error based) in #{datastore['PATH']}.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','PARAMETER',"#{key}","Parameter vulnerable #{key}")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','LOCATION',"QUERY","Parameter located in URI query.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','INJECTION_TYPE',"#{injt}","Injection appears to be treated as a #{injt}.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','VALUE',"#{istr}","String injected using #{idesc} [#{istr}].")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','ERROR_STRING',"#{inje}","Error message found #{inje}")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','DB_TYPE',"#{dbt}","Database type is #{dbt}")							

							break
						end
					else
						print_error("No response")	
						return
					end	
				end 
			end	
		end
		
		#
		# Test DATA parameters
   		#
		
		found = false
		
		if pvars
			sqlinj.each do |istr,idesc|
			
				if found 
					break 
				end
				
				pvars.each do |key,value|		
					pvars = queryparse(datastore['DATA']) #Now its a Hash
				
					print_status("- Testing data with #{idesc}. Parameter #{key}:") 
					pvars[key] = pvars[key]+istr
					
					pvarstr = ""
					pvars.each do |tkey,tvalue|
						if pvarstr
							pvarstr << '&'
						end
						pvarstr << tkey+'='+tvalue
					end
   			
					begin
						testres = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'vars_get' 	=>  gvars,   
							'method'   	=>  datastore['METHOD'],
							'ctype'		=> 'application/x-www-form-urlencoded',
							'cookie'    => datastore['COOKIE'],
							'data'      => pvarstr
						}, 20)
					
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
					rescue ::Timeout::Error, ::Errno::EPIPE			
					end

					if testres
						errorstr.each do |estr,dbtype,injtype|
							if testres.body.include? estr
								found = true
								inje = estr
								dbt = dbtype
								injt = injtype					
							end
						end
			
						if found
							print_status("SQL Injection found.")
							print_status("Error string: '#{inje}' Test Value: #{istr}") 
							print_status("Vuln data parameter: #{key} DB TYPE: #{dbt}, Error type '#{injt}'")
							
							rep_id = wmap_base_report_id(
									wmap_target_host,
									wmap_target_port,
									wmap_target_ssl
							)
							vul_id = wmap_report(rep_id,'VULNERABILITY','ERROR_BASED_SQL_INJECTION',"#{datastore['PATH']}","SQL Injection found (Error based) in #{datastore['PATH']}.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','PARAMETER',"#{key}","Parameter vulnerable #{key}")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','LOCATION',"DATA","Parameter located in request DATA (POST_DATA).")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','INJECTION_TYPE',"#{injt}","Injection appears to be treated as a #{injt}.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','VALUE',"#{istr}","String injected using #{idesc} [#{istr}].")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','ERROR_STRING',"#{inje}","Error message found #{inje}")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','DB_TYPE',"#{dbt}","Database type is #{dbt}")
							
							break
						end
					else
						print_error("No response")	
						return
					end	
				end 
			end	
		end

		#
		# Test COOKIE parameters
   		#
		
		found = false
		
		if datastore['COOKIE']
			sqlinj.each do |istr,idesc|
			
				if found 
					break 
				end
				
				cvars.each do |key,value|		
					cvars = queryparse(datastore['COOKIE']) #Now its a Hash
				
					print_status("- Testing cookie with #{idesc}. Parameter #{key}:") 
					cvars[key] = cvars[key]+istr
					
					cvarstr = ""
					cvars.each do |tkey,tvalue|
						if cvarstr
							cvarstr << ';'
						end
						cvarstr << tkey+'='+tvalue
					end
   			
					begin
						testres = send_request_cgi({
							'uri'  		=>  datastore['PATH'],
							'vars_get' 	=>  gvars,   
							'method'   	=>  datastore['METHOD'],
							'ctype'		=> 'application/x-www-form-urlencoded',
							'cookie'    => cvarstr,
							'data'      => datastore['COOKIE']
						}, 20)
					
					rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
					rescue ::Timeout::Error, ::Errno::EPIPE			
					end

					if testres
						errorstr.each do |estr,dbtype,injtype|
							if testres.body.include? estr
								found = true
								inje = estr
								dbt = dbtype
								injt = injtype					
							end
						end
			
						if found
							print_status("SQL Injection found.")
							print_status("Error string: '#{inje}' Test Value: #{istr}") 
							print_status("Vuln cookie parameter: #{key} DB TYPE: #{dbt}, Error type '#{injt}'")
							
							rep_id = wmap_base_report_id(
									wmap_target_host,
									wmap_target_port,
									wmap_target_ssl
							)
							vul_id = wmap_report(rep_id,'VULNERABILITY','ERROR_BASED_SQL_INJECTION',"#{datastore['PATH']}","SQL Injection found (Error based) in #{datastore['PATH']}.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','PARAMETER',"#{key}","Parameter vulnerable #{key}")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','LOCATION',"COOKIE","Parameter located in Cookies.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','INJECTION_TYPE',"#{injt}","Injection appears to be treated as a #{injt}.")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','VALUE',"#{istr}","String injected using #{idesc} [#{istr}].")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','ERROR_STRING',"#{inje}","Error message found #{inje}")
							wmap_report(vul_id,'ERROR_BASED_SQL_INJECTION','DB_TYPE',"#{dbt}","Database type is #{dbt}")
							
							break
						end
					else
						print_error("No response")	
						return
					end	
				end 
			end	
		end				
	end
end
