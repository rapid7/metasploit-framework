module Msf
class Post

module Accounts

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
end # Post
end # Msf
