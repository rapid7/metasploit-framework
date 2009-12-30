##
# $Id$
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
	include Msf::Auxiliary::Report


	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Error Based SQL Injection Scanner',
			'Description'	=> %q{
				This module identifies the existence of Error Based SQL injection issues. Still requires alot of work
					
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('METHOD', [ true, "HTTP Method",'GET']),
				OptString.new('PATH', [ true,  "The path/file to test SQL injection", '/default.aspx']),
				OptString.new('QUERY', [ false,  "HTTP URI Query", '']),
				OptString.new('DATA', [ false, "HTTP Body Data", '']),
				OptString.new('COOKIE',[ false, "HTTP Cookies", ''])
			], self.class)
		
		register_advanced_options(
			[
				OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ])
			], self.class)
						
	end

	def run_host(ip)
	
		gvars = nil
		pvars = nil
		cvars = nil
	
		
	
		sqlinj = [
			[ "'" ,'Single quote'],
			[ "')",'Single quote and parenthesis'],
			[ "\"",'Double quote'],
			[ "#{rand(10)}'", 'Random value with single quote']		
		]
	
		errorstr = [
			["Unclosed quotation mark after the character string",'MSSQL','string'],
			["Syntax error in string in query expression",'MSSQL','string'],
			["Microsoft OLE DB Provider",'MSSQL','unknown'],
			["You have an error in your SQL syntax",'MySQL','unknown'],
			["java.sql.SQLException",'unknown','unknown']	
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
		
		if !datastore['NoDetailMessages']
			print_status("Normal request sent.")  
		end
		
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
				print_error("[#{wmap_target_host}] Error string appears in the normal response, unable to test")
				print_error("[#{wmap_target_host}] Error string: '#{inje}'") 
				print_error("[#{wmap_target_host}] DB TYPE: #{dbt}, Error type '#{injt}'")
				
				report_note(
					:host	=> ip,
					:proto	=> 'HTTP',
					:port	=> rport,
					:type	=> 'DATABASE_ERROR',
					:data	=> "#{datastore['PATH']} Error: #{inje} DB: #{dbt}"
				)
				
				return
			end
		else
			print_error("[#{wmap_target_host}] No response")
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
					gvars[key] = gvars[key]+istr
					
					if !datastore['NoDetailMessages']
						print_status("- Testing query with #{idesc}. Parameter #{key}:") 
					end
					
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
							print_status("[#{wmap_target_host}] SQL Injection found. (#{idesc}) (#{datastore['PATH']})")
							print_status("[#{wmap_target_host}] Error string: '#{inje}' Test Value: #{gvars[key]}") 
							print_status("[#{wmap_target_host}] Vuln query parameter: #{key} DB TYPE: #{dbt}, Error type '#{injt}'")
							
							report_note(
								:host	=> ip,
								:proto	=> 'HTTP',
								:port	=> rport,
								:type	=> 'SQL_INJECTION',
								:data	=> "#{datastore['PATH']} Location: QUERY Parameter: #{key} Value: #{istr} Error: #{inje} DB: #{dbt}"
							)
							
							break
						end
					else
						print_error("[#{wmap_target_host}] No response")	
						return
					end	
				end 
			end	
			gvars = queryparse(datastore['QUERY'])
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
				
					if !datastore['NoDetailMessages']
						print_status("- Testing data with #{idesc}. Parameter #{key}:") 
					end
					
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
							print_status("[#{wmap_target_host}] SQL Injection found. (#{idesc}) (#{datastore['PATH']})")
							print_status("[#{wmap_target_host}] Error string: '#{inje}' Test Value: #{istr}") 
							print_status("[#{wmap_target_host}] Vuln data parameter: #{key} DB TYPE: #{dbt}, Error type '#{injt}'")
							
							report_note(
								:host	=> ip,
								:proto	=> 'HTTP',
								:port	=> rport,
								:type	=> 'SQL_INJECTION',
								:data	=> "#{datastore['PATH']} Location: DATA Parameter: #{key} Value: #{istr} Error: #{inje} DB: #{dbt}"
							)
							
							break
						end
					else
						print_error("[#{wmap_target_host}] No response")	
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
				
					if !datastore['NoDetailMessages']
						print_status("- Testing cookie with #{idesc}. Parameter #{key}:") 
					end
					
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
							print_status("[#{wmap_target_host}] SQL Injection found. (#{idesc}) (#{datastore['PATH']})")
							print_status("[#{wmap_target_host}] Error string: '#{inje}' Test Value: #{istr}") 
							print_status("[#{wmap_target_host}] Vuln cookie parameter: #{key} DB TYPE: #{dbt}, Error type '#{injt}'")
							
							report_note(
								:host	=> ip,
								:proto	=> 'HTTP',
								:port	=> rport,
								:type	=> 'SQL_INJECTION',
								:data	=> "#{datastore['PATH']} Location: COOKIE Parameter: #{key} Value: #{istr} Error: #{inje} DB: #{dbt}"
							)
							
							break
						end
					else
						print_error("[#{wmap_target_host}] No response")	
						return
					end	
				end 
			end	
		end				
	end
end
