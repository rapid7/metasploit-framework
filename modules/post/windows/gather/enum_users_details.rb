require 'msf/core'
require 'rex/text'
require 'msf/core/post/windows/accounts'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Accounts

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Enumerate Users and Details',
				'Description'   => %q{ This module enumerates users and their details.
							The information is gathered purely through WinAPI calls, meaning this
							module leaves less of a trace than executing commands. The information
							reported (with the exception of group info) corresponds to the various
							USER_INFO data structures that NetAPI32's NetUserEnum function returns
							and can be controlled in the same manner with this module's 'LEVEL' option.
							Not all levels are supported on all operating systems, see the documentation
							for NetUserEnum (http://goo.gl/JdjKa) for more information. Also, the
							amount of information may further be restricted depending on the
							session's privileges. Note, Computer accounts are shown (and designated as such).
							},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'chao-mu'],
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

		register_options(
			[
				OptEnum.new('LEVEL', [true, 'Corresponds to the "levels" used by NetUserEnum',
						3, USER_INFO_LEVELS.keys]),
				OptBool.new('GROUP_INFO', [true, 'Display local and global group information', false]),
				OptEnum.new('SHOWN', [true, 'What kind of accounts will be enumerated',
						:all, ENUM_USERS_FILTERS.keys]),
				OptString.new('SERVER', [false, 'Server on which to run this command']),
			], self.class)
	end

	# Descriptions are from http://msdn.microsoft.com/en-us/library/aa371338%28v=vs.85%29.aspx
	USER_FLAG_TO_DESCRIPTION = {
		:logon_script_executed => 'The logon script executed',
		:account_disabled      => 'Acount is disabled',
		:homedir_required      => 'The home directory is required',
		:password_not_required => 'No password required',
		:password_cant_change  => 'User cannot change their password',
		:locked_out            => 'Account is currently locked out',
		:dont_expire_password  => 'Password should never expire',
		:encrypted_text_password_allowed => 'Password is stored under reversible encryption in the Active Directory',
		:not_delegated => 'Other users cannot act as delegates of this user account',
		:smartcard_required => 'User is required to log on with a smart card',
		:use_des_key_only => 'Principal restricted to use only DES encryption types for keys',
		:dont_require_preauth => 'Acount does not require Kerberos preauthentication for logon',
		:trusted_for_delegation => 'Account is enabled for delegation',
		:password_expired => 'Password has expired',
		:trusted_to_authenticate_for_delegation => 'Account is trusted to authenticate a user outside of the Kerberos security package and delegate that user through constrained delegation',
		:normal_account => 'Account type represents a typical user',
		:temp_duplicate_account => 'This account is for a user whose primary account is in another domain',
		:workstation_trust_account => 'This is a computer account for a computer that is a member of this domain',
		:server_trust_account => 'This is a computer account for a backup domain controller that is a member of this domain',
		:interdomain_trust_account => 'This is a permit to trust account for a domain that trusts other domains',
	}

	USER_INFO_REPORTS = [
		[:comment, 'Comment'],
		[:priv, 'Privilege level'],
		[:password_age, 'Seconds since password last changed'],
		[:home_dir, 'Home directory'],
		[:script_path, 'Logon script'],
		[:full_name, 'Full name'],
		[:workstations, 'Workstations user can log into'],
		[:last_logon, 'Seconds since last logon (known to us)'],
		[:last_logoff, 'Seconds since last logoff (known to us)'],
		[:acct_expires, 'Account expiration date in POSIX time'],
		[:max_storage, 'Max storage'],
		[:bad_pw_count, 'Number of times user entered incorrect password (known to us)'],
		[:num_logons, 'Number of successful logons (known to us)'],
		[:country_code, 'Country/region code for language choice'],
		[:code_page, 'Code page for language choice'],
		[:user_id, 'Relative ID (RID) of user'],
		[:primary_group_id, 'RID of Primary Global Group for the user'],
		[:profile, 'Path to the user\'s profile'],
		[:home_dir_drive, 'Drive letter of user\'s home directory'],
	]

	def run
		server = datastore['SERVER']

		print_status 'Enumerating users...'
		users = enum_users(datastore['LEVEL'].to_i, :all, server) or return

		users.each do |user_info|
			account_name = user_info[:name]
			print_good 'Account name: ' << account_name

			USER_INFO_REPORTS.each do |key, description|
				if user_info.has_key?(key) && user_info[key] != :unknown
					value = user_info[key]

					if value.class == String && value.empty?
						next
					end

					print_line "#{description}: #{value.to_s}"
				end
			end

			if user_info.has_key?(:password_expired) && user_info[:password_expired]
				print_line 'Password has expired'
			end

			if user_info.has_key?(:flags)
				flag_descriptions = []

				user_info[:flags].each do |flag, value|
					if value && ![:normal_account, :logon_script_executed].include?(flag)
						flag_descriptions.push(USER_FLAG_TO_DESCRIPTION[flag])
					end
				end

				unless flag_descriptions.empty?
					print_line 'Notable flags: '
					flag_descriptions.each do |description|
						print_line '    ' << description
					end
				end
			end

			if user_info.has_key?(:auth_flags) && !user_info[:auth_flags].empty?
				print_line 'Auth flags: '

				user_info[:auth_flags].each do |flag, value|
					print_line "    #{flag.to_s}: #{value.to_s}"
				end
			end

			if datastore['GROUP_INFO']
				[:local, :global].each do |group_type|
					groups = get_user_groups(account_name, group_type, server) or next

					unless groups.empty?
						group_names = groups.map{|g| g[:name]}.join(', ')
						friendly_type = group_type.to_s.capitalize

						print_line friendly_type << ' groups: ' << group_names
					end
				end
			end
		end

	end
end
