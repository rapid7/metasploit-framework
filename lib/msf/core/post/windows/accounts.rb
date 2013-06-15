# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_netapi32'

module Msf
class Post
module Windows

module Accounts
 
	# We will want to access the data types defined therein, but not have to type it out
	NETAPI32_DEF = Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::Def::Def_netapi32

	# WinAPI constant name to friendly symbol
	USER_AUTH_FLAGS = {
		'AF_OP_PRINT'  => :printer_operator,
		'AF_OP_COMM'   => :communications_operator,
		'AF_OP_SERVER' => :server_operator,
		'AF_OP_COMM'   => :accounts_operator,
	}

	# WinAPI constant name to friendly symbol
	USER_FLAGS = {
		'UF_SCRIPT' => :logon_script_executed,
		'UF_ACCOUNTDISABLE' => :account_disabled,
		'UF_HOMEDIR_REQUIRED' => :homedir_required,
		'UF_PASSWD_NOTREQD' => :password_not_required,
		'UF_PASSWD_CANT_CHANGE' => :password_cant_change,
		'UF_LOCKOUT' => :locked_out,
		'UF_DONT_EXPIRE_PASSWD' => :dont_expire_password,
		'UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED' => :encrypted_text_password_allowed,
		'UF_NOT_DELEGATED' => :not_delegated,
		'UF_SMARTCARD_REQUIRED' => :smartcard_required,
		'UF_USE_DES_KEY_ONLY' => :use_des_key_only,
		'UF_DONT_REQUIRE_PREAUTH' => :dont_require_preauth,
		'UF_TRUSTED_FOR_DELEGATION' => :trusted_for_delegation,
		# Windows 2000:  This value is not supported.
		'UF_PASSWORD_EXPIRED' => :password_expired,
		# Windows XP/2000:  This value is not supported.
		'UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION' => :trusted_to_authenticate_for_delegation,
		'UF_NORMAL_ACCOUNT' => :normal_account,
		'UF_TEMP_DUPLICATE_ACCOUNT' => :temp_duplicate_account,
		'UF_WORKSTATION_TRUST_ACCOUNT' => :workstation_trust_account,
		'UF_SERVER_TRUST_ACCOUNT' => :server_trust_account,
		'UF_INTERDOMAIN_TRUST_ACCOUNT' => :interdomain_trust_account
	}

	# Symbols to integers recognized by NetUserEnum for the 'filter' param
	#   or WinAPI constant names for such values
	ENUM_USERS_FILTERS = {
		:all => 0,
		:normal_account => 'FILTER_NORMAL_ACCOUNT',
		:temp_duplicate_account => 'FILTER_TEMP_DUPLICATE_ACCOUNT',
		:workstation_trust_account => 'FILTER_WORKSTATION_TRUST_ACCOUNT',
		:server_trust_account => 'FILTER_SERVER_TRUST_ACCOUNT',
		:interdomain_trust_account => 'FILTER_INTERDOMAIN_TRUST_ACCOUNT',
	}

	# Levels enum_users(...) supports and the corresponding data structure type
	USER_INFO_LEVELS = {
		0 => NETAPI32_DEF::USER_INFO_0,
		1 => NETAPI32_DEF::USER_INFO_1,
		2 => NETAPI32_DEF::USER_INFO_2,
		3 => NETAPI32_DEF::USER_INFO_3,
	}

	###
	# enum_users(level, filter_sym = :all, server_name = nil)
	#
	# Summary:
	#    Enumerates information regarding all of this system's users.
	#
	# Parameters
	#    level: Numeric level of information. USER_INFO_LEVELS contains supported levels
	#           To see a description of levels and the information they provide,
	#           see http://msdn.microsoft.com/en-us/library/aa370652%28v=vs.85%29.aspx
	#    filter_sym (opt): Specifies the type of accounts included. See ENUM_USERS_FILTERS
	#    server_name (opt): The computer on which to run this. nil is this/victim computer
	#
	# Returns:
	#    An array of hashes containing user information relative to the given "level"
	#
	# Caveats:
	#    On errors, error information is printed and nil is returned
	#    You will get Computer accounts
	#    Underprivileged users will get partial information or errors
 	##
	def enum_users(level, filter_sym = :all, server_name = nil)
		util = client.railgun.util
		netapi = client.railgun.netapi32

		user_info_type = USER_INFO_LEVELS[level]
		filter = ENUM_USERS_FILTERS[filter_sym]

		# Call http://msdn.microsoft.com/en-us/library/aa370652%28v=vs.85%29.aspx
		result = netapi.NetUserEnum(
			server_name,
			level,
			filter,
			8,#bufptr - allocate 8 bytes for both x86 and x64 pointers
			-1,#prefmaxlen
			4,#entriesread - railgun wants us to pass in 4 since this is PDWORD
			4,#totalentries - railgun wants us to pass in 4 since this is PDWORD
			0) #resume_handle

		# NET_API_STATUS
		status = result['return']

		# get the pointer to the USER_INFO_X array
		bufptr = util.read_pointer(result['bufptr'])

		# Check that the call succeeded.
		unless status == 0
			print_error 'Unable to enumerate users:' <<
				" Failed with error code #{result['GetLastError']}" <<
				" and NET_API_STATUS of #{status}"

			unless util.is_null_pointer(bufptr)
				netapi.NetApiBufferFree(bufptr)
			end

			return nil
		end


		# The hashes we will return to the caller after beautification
		clean_user_info_hashes = []

		# get the ammount of entries in the USER_INFO_X array
		entries_read = result['entriesread']

		# loop through the read entries in the USER_INFO_X array
		util.read_array(user_info_type, entries_read, bufptr).each do |info|
			# We want to "clean" the info, as in make it useful outside of WinAPI
			clean_user_info_hashes.push(clean_USER_INFO_N(info))
		end

		# Clean up time! LNT
		netapi.NetApiBufferFree(bufptr)

		return clean_user_info_hashes
	end

	###
	# get_user_groups(username, type, servername = nil)
	#
	# Summary:
	#    Enumerates local or global groups
	#
	# Parameters:
	#    username   - The user's account name
	#    type       - Dictates the type of group to list. either :global or :local
	#    servername - The computer onwhich to run the WinAPI calls
	#
	# Caveats:
	#    On errors, error information is printed and nil is returned
	#
	# Returns:
	#    An array containing a hash for each group. Currently :name is the only key
	##
	def get_user_groups(username, type, servername = nil)
		netapi = client.railgun.netapi32
		util = client.railgun.util

		result = case type
		when :global
			netapi.NetUserGetGroups(servername, username, 0, 8, 0xFFFFFFFF, 4, 4)
		when :local
			netapi.NetUserGetLocalGroups(servername, username, 0, 0, 8, 0xFFFFFFFF, 4, 4)
		else
			raise ArgumentError, "get_user_groups type must be :global or :local"
		end

		# NET_API_STATUS
		status = result['return']

		# get the pointer to the GROUP_USERS_INFO_0 array
		bufptr = util.unpack_pointer(result['bufptr'])

		# Check that the call succeeded.
		unless status == 0
			print_error 'Unable to enumerate groups:' <<
				" Failed with error code #{result['GetLastError']}" <<
				" and NET_API_STATUS of #{status}"

			unless util.is_null_pointer(bufptr)
				netapi.NetApiBufferFree(bufptr)
			end

			return nil
		end

		entries_read = result['entriesread']

		groups = util.read_array(NETAPI32_DEF::GROUP_USERS_INFO_0, entries_read, bufptr)

		if groups.length == 1 && groups[0][:name] == 'None'
			return []
		end

		return groups
	end

	###
	# clean_USER_INFO_N(struct)
	#
	# Summary:
	#    Takes a USER_INFO_ hash and strips out or translates the parts
	#    that would be useless outside of interacting with railgun/winapi
	#
	# Mappings:
	#    :priv         => :guest, :user, or :admin
	#    :auth_flags   => Becomes a hash with symbols to true/false, see USER_AUTH_FLAGS
	#    :flags        => Becomes a hash with symbols to true/false, see USER_FLAGS
	#    :acct_expires => Same value, except :never if never
	#    :max_storage  => Same value, except :unlimited if unlimited
	#    :last_logon, :last_logoff, :password_age => Same value, except 'unknown' if unknown
	#
	# Deleted:
	#    :password (will be unavailable. Please prove me wrong!)
	#    :units_per_week, logon_hours (TODO: write the algorithm to calculate the latter)
	##
	def clean_USER_INFO_N(struct)
		user_info = {}
		rg = client.railgun

		# Copy over everything (using a symbol as the key) before pruning
		struct.each do |key, value|
			user_info[key] = value
		end

		# usriX_password will be empty
		# LPWSTR usri3_password
		user_info.delete(:password)

		if struct.has_key?(:priv)
			user_info[:priv] = case struct[:priv]
				when rg.const('USER_PRIV_GUEST') then :guest
				when rg.const('USER_PRIV_USER')  then :user
				when rg.const('USER_PRIV_ADMIN') then :admin
			end
		end

		# Break apart the flags into symbols
		{
			:auth_flags => USER_AUTH_FLAGS,
			:flags      => USER_FLAGS
		}.each do |key, flag_mappings|
			if user_info.has_key?(key)
				user_info[key] = rg.util.judge_bit_field(user_info[key], flag_mappings)
			end
		end

		[:last_logon, :last_logoff, :password_age].each do |key|
			if user_info.has_key?(key)
				time = user_info[key]

				user_info[key] = (time == 0 ? :unknown : time)
			end
		end

		if user_info.has_key?(:acct_expires)
			expiry = user_info[:acct_expires]

			#TODO: Add TIMEQ_FOREVER to constant manager? -1
			user_info[:acct_expires] = (expiry == 4294967295 ? :never : expiry)
		end

		if user_info.has_key?(:max_storage)
			limit = user_info[:max_storage]

			#TODO: Add USER_MAXSTORAGE_UNLIMITED to constant manager? -1
			user_info[:max_storage] = (limit == 4294967295 ? :unlimited : limit)
		end

		# TODO: Implement the algorithm to calculate logon_hours (see USER_INFO_3 docs)
		[:units_per_week, :logon_hours].each do |x|
			user_info.delete(x)
		end

		return user_info
	end



	##
	# delete_user(username, server_name = nil)
	#
	# Summary:
	#   Deletes a user account from the given server (or local if none given)
	#
	# Parameters
	#   username    - The username of the user to delete (not-qualified, e.g. BOB)
	#   server_name - DNS or NetBIOS name of remote server on which to delete user
	#
	# Returns:
	#   One of the following:
	#      :success          - Everything went as planned
	#      :invalid_server   - The server name provided was invalid
	#      :not_on_primary   - Operation allowed only on domain controller
	#      :user_not_found   - User specified does not exist on the given server
	#      :access_denied    - You do not have permission to delete the given user
	#
	#   OR nil if there was an exceptional windows error (example: ran out of memory)
	#
	# Caveats:
	#   nil is returned if there is an *exceptional* windows error. That error is printed.
	#   Everything other than ':success' signifies failure
	##
	def delete_user(username, server_name = nil)
		deletion = client.railgun.netapi32.NetUserDel(server_name, username)

		#http://msdn.microsoft.com/en-us/library/aa370674.aspx
		case deletion['return']
		when 2221 # NERR_UserNotFound
			return :user_not_found
		when 2351 # NERR_InvalidComputer
			return :invalid_server
		when 2226 # NERR_NotPrimary
			return :not_on_primary
		when client.railgun.const('ERROR_ACCESS_DENIED')
			return :access_denied
		when 0
			return :success
		else
			error = deletion['GetLastError']
			if error != 0
				print_error "Unexpected Windows System Error #{error}"
			else
				# Uh... we shouldn't be here
				print_error "DeleteUser unexpectedly returned #{deletion['return']}"
			end
		end

		# If we got here, then something above failed
		return nil
	end


	##
	# resolve_sid(sid, system_name = nil)
	#
	# Summary:
	#   Retrieves the name, domain, and type of account for the given sid
	#
	# Parameters:
	#   sid         - A SID string (e.g. S-1-5-32-544)
	#   system_name - Where to search. If nil, first local system then trusted DCs
	#
	# Returns:
	#   {
	#     :name   => account name (e.g. "SYSTEM")
	#     :domain => domain where the account name was found. May have values such as
	#                the work station's name, BUILTIN, NT AUTHORITY, or an empty string
	#     :type   => one of :user, :group, :domain, :alias, :well_known_group,
	#                :deleted_account, :invalid, :unknown, :computer
	#     :mapped => There was a mapping found for the SID
	#   }
	#
	#   OR nil if there was an exceptional windows error (example: ran out of memory)
	#
	# Caveats:
	#   If a valid mapping is not found, only { :mapped => false } will be returned
	#   nil is returned if there is an *exceptional* windows error. That error is printed.
	#   If an invalid system_name is provided, there will be a windows error and nil returned
	##
	def resolve_sid(sid, system_name = nil)
		adv = client.railgun.advapi32;

		# Second param is the size of the buffer where the pointer will be written
		# In railgun, if you specify 4 bytes for a PDWORD it will grow to 8, as needed.
		conversion = adv.ConvertStringSidToSidA(sid, 4)

		# If the call failed, handle errors accordingly.
		unless conversion['return']
			error = conversion['GetLastError']

			case error
			when client.railgun.const('ERROR_INVALID_SID')
				# An invalid SID was supplied
				return { :type => :invalid, :mapped => false }
			else
				print_error "Unexpected windows error #{error}"
				return nil
			end
		end

		# A reference to the SID data structure. Generally needed when working with sids
		psid = conversion['pSid']

		# http://msdn.microsoft.com/en-us/library/aa379166(v=vs.85).aspx
		# TODO: The buffer sizes here need to be reviewed/adjusted/optimized
		lookup = adv.LookupAccountSidA(system_name, psid, 100, 100, 100, 100, 1)

		# We no longer need the sid so free it.
		# NOTE: We do not check to see if this call succeeded. Do we care?
		adv.FreeSid(psid)

		# If the call failed, handle errors accordingly.
		unless lookup['return']
			error = lookup['GetLastError']

			case error
			when client.railgun.const('ERROR_INVALID_PARAMETER')
				# Unless the railgun call is broken, this means revesion is wrong
				return { :type => :invalid }
			when client.railgun.const('ERROR_NONE_MAPPED')
				# There were no accounts associated with this SID
				return { :mapped => false }
			else
				print_error "Unexpected windows error #{error}"
				return nil
			end
		end

		# peUse is the enum "SID_NAME_USE"
		sid_type = lookup_SID_NAME_USE(lookup['peUse'].unpack('C')[0])

		return {
			:name   => lookup['Name'],
			:domain => lookup['ReferencedDomainName'],
			:type   => sid_type,
			:mapped => true
		}
	end

	private

	##
	# Converts a WinAPI's SID_NAME_USE enum to a symbol
	# Symbols are (in order) :user, :group, :domain, :alias, :well_known_group,
	#                        :deleted_account, :invalid, :unknown, :computer
	##
	def lookup_SID_NAME_USE(enum_value)
		[
			# SidTypeUser = 1
			:user,
			# SidTypeGroup,
			:group,
			#SidTypeDomain,
			:domain,
			#SidTypeAlias,
			:alias,
			#SidTypeWellKnownGroup,
			:well_known_group,
			#SidTypeDeletedAccount,
			:deleted_account,
			#SidTypeInvalid,
			:invalid,
			#SidTypeUnknown,
			:unknown,
			#SidTypeComputer,
			:computer,
			#SidTypeLabel
			:integrity_label
		][enum_value - 1]
	end
end # Accounts
end # Windows
end # Post
end # Msf
