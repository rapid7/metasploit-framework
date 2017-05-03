##
# $Id: error_sql_injection.rb 11796 2011-02-22 20:49:44Z jduck $
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
			'Name'   		=> 'HTTP XSS basic Scanner',
			'Description'	=> %q{
				This module identifies the existence of basic XSS issues. Still requires alot of work! This module is based on the error based SQL injection module of et. 
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ,
							'm-1-k-3' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$',
			'References'	=>
						[
							['CWE', '79'],
							['Cert Advisory', 'CA-2000-02'],
							['URL', 'http://ha.ckers.org/xss.html']
						]
			))
		register_options(
			[
				OptString.new('METHOD', [ true, "HTTP Method",'GET']),
				OptString.new('PATH', [ true,  "The path/file to test XSS", '/default.aspx']),
				OptString.new('QUERY', [ false,  "HTTP URI Query", '']),
				OptString.new('DATA', [ false,  "HTTP Body/Data Query", ''])
			], self.class)

		register_advanced_options(
			[
				OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ])
			], self.class)

	end

	def run_host(ip)

		qvars = nil
		#the xss test strings need more testing
		xssinj = [
			[ "\"><script>alert(1)</script>" ,'basic check'],
			[ "\"><SCriPt>prompt(1)</SCriPt>" ,'basic check 1'],
			[ "\'\"><SCriPt>prompt(1)</SCriPt>" ,'basic check 2'],
			[ "\\\"><SCriPt>prompt(1)</SCriPt>" ,'basic check 2'],
			[ "%22%3e%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e" ,'basic check URL encoded'],
			["<script>alert(\"XSS\")</script>" ,'advanced check'],
			["<script>alert(document.cookie)</script>" ,'advanced check'],
			["\'><script>alert(document.cookie)</script>" ,'advanced check'],
			["\'><script>alert(document.cookie);</script>" ,'advanced check'],
			["\"><img src=x onerror=alert(1)>" ,'advanced check'],
			["\"><div onclick=\"alert(1)\">" ,'advanced check'],
			["\"><div style=\"background:url(javascript:alert(1))\">" ,'advanced check'],
			["\"><BODY ONLOAD=alert(1)>" ,'advanced check'],

		]
		#the xss response strings need more testing
		errorstr = [
			["<script>alert(1)</script>",'reflective XSS','basic check'],
			["<SCriPt>prompt(1)</SCriPt>",'reflective XSS','basic check'],
			["<script>alert(\"XSS\")</script>" ,'reflective XSS','advanced check'],
			["<script>alert(document.cookie)</script>" ,'reflective XSS','advanced check'],
			["\'><script>alert(document.cookie)</script>" ,'reflective XSS','advanced check'],
			["\'><script>alert(document.cookie);</script>" ,'reflective XSS','advanced check'],
			["\"><img src=x onerror=alert(1)>" ,'reflective XSS','advanced check'],
			["\"><div onclick=\"alert(1)\">" ,'reflective XSS','advanced check'],
			["\"><div style=\"background:url(javascript:alert(1))\">" ,'reflective XSS','advanced check'],
			["\"><BODY ONLOAD=alert(1)>" ,'reflective XSS','advanced check'],
		]

		#
		# Dealing with empty query/data and making them hashes.
		#

		if  datastore['METHOD'] =='GET'
			if not datastore['QUERY'].empty?
				qvars = queryparse(datastore['QUERY']) #Now its a Hash
			else
				return
			end
		else
			if not datastore['DATA'].empty?
				qvars = queryparse(datastore['DATA']) #Now its a Hash
			else
				return
			end
		end

		#
		# Send normal request to check if error is generated
		# (means the error is caused by other means)
		#
		#

		if datastore['METHOD'] == 'POST'
			reqinfo = {
				'uri'  		=> datastore['PATH'],
				'query' 	=> datastore['QUERY'],
				'data' 		=> datastore['DATA'],
				'method'   	=> datastore['METHOD'],
				'ctype'		=> 'application/x-www-form-urlencoded',
				'encode'	=> false
			}
		else
			reqinfo = {
				'uri'  		=> datastore['PATH'],
				'query' 	=> datastore['QUERY'],
				'method'   	=> datastore['METHOD'],
				'ctype'		=> 'application/x-www-form-urlencoded',
				'encode'	=> false
			}
		end

		begin
			normalres = send_request_raw(reqinfo, 20)

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
				print_error("[#{wmap_target_host}] Vuln: #{dbt}")

				#its a vulnerability
				report_vuln(
					:host	=> ip,
					:proto	=> 'tcp',
					:name	=> self.fullname,
					:port	=> rport,
					:refs	=> self.references
				)
				#but we need more info ... so lets report also a note
				report_note(
					:host	=> ip,
					:proto	=> 'tcp',
					:name	=> self.fullname,
					:sname	=> 'HTTP',
					:port	=> rport,
					:type	=> 'XSS_Vuln',
					:data	=> "#{datastore['PATH']} Location: QUERY Parameter: #{key} Value: #{istr} Error: #{inje} Vuln: #{dbt}",
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

		if qvars
			xssinj.each do |istr,idesc|

				if found
					break
				end

				qvars.each do |key,value|
					if datastore['METHOD'] == 'POST'
						qvars = queryparse(datastore['DATA']) #Now its a Hash
					else
						qvars = queryparse(datastore['QUERY']) #Now its a Hash
					end
					qvars[key] = qvars[key]+istr

					if !datastore['NoDetailMessages']
						print_status("- Testing query with #{idesc}. Parameter #{key}:")
					end

					fstr = ""
					qvars.each_pair do |var,val|
						fstr += var+"="+val+"&"
					end

					if datastore['METHOD'] == 'POST'
						reqinfo = {
							'uri'  		=> datastore['PATH'],
							'query'		=> datastore['QUERY'],
							'data' 		=> fstr,
							'method'   	=> datastore['METHOD'],
							'ctype'		=> 'application/x-www-form-urlencoded',
							'encode'	=> false
						}
					else
						reqinfo = {
							'uri'  		=> datastore['PATH'],
							'query' 	=> fstr,
							'method'   	=> datastore['METHOD'],
							'ctype'		=> 'application/x-www-form-urlencoded',
							'encode'	=> false
						}
					end

					begin

						testres = send_request_raw(reqinfo, 20)

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
							print_status("[#{wmap_target_host}] possible XSS vulnerability found. (#{idesc}) (#{datastore['PATH']})")
							print_status("[#{wmap_target_host}] XSS string: '#{inje}' Test Value: #{qvars[key]}")
							print_status("[#{wmap_target_host}] Vuln query parameter: #{key} / XSS-TYPE: #{dbt}, Test type '#{injt}'")

							report_vuln(
								:host	=> ip,
								:proto  	=> 'tcp',
								:name	=> self.fullname,
								:port	=> rport,
								:refs   	=> self.references
							)
							#but we need more info ... so lets report also a note
							report_note(
								:host	=> ip,
								:proto	=> 'tcp',
								:name	=> self.fullname,
								:sname	=> 'HTTP',
								:port	=> rport,
								:type	=> 'XSS_Vuln',
								:data	=> "#{datastore['PATH']} Location: QUERY Parameter: #{key} Value: #{istr} Error: #{inje} Vuln: #{dbt}",
							)
							return
						end
					else
						print_error("[#{wmap_target_host}] No response")
						return
					end
				end
			end

			if datastore['METHOD'] == 'POST'
				qvars = queryparse(datastore['DATA']) #Now its a Hash
			else
				qvars = queryparse(datastore['QUERY']) #Now its a Hash
			end
		end
	end
end
