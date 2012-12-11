# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_netapi32

	GROUP_USERS_INFO_0 = [
		[:name, :LPWSTR]
	]
 
	USER_INFO_0 = [
		[:name, :LPWSTR]
	]

	USER_INFO_1 = [
		[:name, :LPWSTR],
		[:password, :LPWSTR],
		[:password_age, :DWORD],
		[:priv, :DWORD],
		[:home_dir, :LPWSTR],
		[:comment, :LPWSTR],
		[:flags, :DWORD],
		[:script_path, :LPWSTR]
	]

	USER_INFO_2 = [
		[:name, :LPWSTR],
		[:password, :LPWSTR],
		[:password_age, :DWORD],
		[:priv, :DWORD],
		[:home_dir, :LPWSTR],
		[:comment, :LPWSTR],
		[:flags, :DWORD],
		[:script_path, :LPWSTR],
		[:auth_flags, :DWORD],
		[:full_name, :LPWSTR],
		[:usr_comment, :LPWSTR],
		[:parms, :LPWSTR],
		[:workstations, :LPWSTR],
		[:last_logon, :DWORD],
		[:last_logoff, :DWORD],
		[:acct_expires, :DWORD],
		[:max_storage, :DWORD],
		[:units_per_week, :DWORD],
		[:logon_hours, :PBYTE],
		[:bad_pw_count, :DWORD],
		[:num_logons, :DWORD],
		[:logon_server, :LPWSTR],
		[:country_code, :DWORD],
		[:code_page, :DWORD]
	]

	USER_INFO_3 = [
		[:name, :LPWSTR],
		[:password, :LPWSTR],
		[:password_age, :DWORD],
		[:priv, :DWORD],
		[:home_dir, :LPWSTR],
		[:comment, :LPWSTR],
		[:flags, :DWORD],
		[:script_path, :LPWSTR],
		[:auth_flags, :DWORD],
		[:full_name, :LPWSTR],
		[:usr_comment, :LPWSTR],
		[:parms, :LPWSTR],
		[:workstations, :LPWSTR],
		[:last_logon, :DWORD],
		[:last_logoff, :DWORD],
		[:acct_expires, :DWORD],
		[:max_storage, :DWORD],
		[:units_per_week, :DWORD],
		[:logon_hours, :PBYTE],
		[:bad_pw_count, :DWORD],
		[:num_logons, :DWORD],
		[:logon_server, :LPWSTR],
		[:country_code, :DWORD],
		[:code_page, :DWORD],
		[:user_id, :DWORD],
		[:primary_group_id, :DWORD],
		[:profile, :LPWSTR],
		[:home_dir_drive, :LPWSTR],
		[:password_expired, :DWORD]
	]

	SERVER_INFO_101 = [
		[:platform_id, :DWORD],
		[:name, :LPWSTR],
		[:version_major, :DWORD],
		[:version_minor, :DWORD],
		[:type, :DWORD],
		[:comment, :LPWSTR]
	]

	SERVER_INFO_102 = [
		[:platform_id, :DWORD],
		[:name, :LPWSTR],
		[:version_major, :DWORD],
		[:version_minor, :DWORD],
		[:type, :DWORD],
		[:comment, :LPWSTR],
		[:users, :DWORD],
		[:disc, :LONG],
		[:hidden, :BOOL],
		[:announce, :DWORD],
		[:anndelta, :DWORD],
		[:licenses, :DWORD],
		[:userpath, :LPWSTR]
	]

	def self.create_dll(dll_path = 'netapi32')
		dll = DLL.new(dll_path, ApiConstants.manager)

		dll.add_function('NetUserDel', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","username","in"],
		])

		dll.add_function('NetGetJoinInformation', 'DWORD',[
			["PWCHAR","lpServer","in"],
			["PDWORD","lpNameBuffer","out"],
			["PDWORD","BufferType","out"]
		])

		dll.add_function('NetServerGetInfo', 'DWORD',[
			["PWCHAR","servername","in"],
			["DWORD","level","in"],
			["PDWORD","bufptr","out"],
		])

		# http://msdn.microsoft.com/en-us/library/aa370653%28v=vs.85%29.aspx
		dll.add_function('NetUserGetGroups', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","username","in"],
			["DWORD","level","in"],
			# __out  LPBYTE *bufptr,
			["PBLOB","bufptr","out"],
			["DWORD","prefmaxlen","in"],
			["PDWORD","entriesread","out"],
			["PDWORD","totalentries","out"],
		])

		# http://msdn.microsoft.com/en-us/library/aa370655(v=VS.85).aspx
		dll.add_function('NetUserGetLocalGroups', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","username","in"],
			["DWORD","level","in"],
			["DWORD","flags","in"],
			# __out  LPBYTE *bufptr,
			["PBLOB","bufptr","out"],
			["DWORD","prefmaxlen","in"],
			["PDWORD","entriesread","out"],
			["PDWORD","totalentries","out"],
		])

		# http://msdn.microsoft.com/en-us/library/aa370652(VS.85).aspx 
		dll.add_function('NetUserEnum', 'DWORD',[
			["PCHAR","servername","in"],
			["DWORD", "level", 'in'],
			["DWORD", "filter","in"],
			['PBLOB', 'bufptr', 'out'],
			['DWORD', 'prefmaxlen','in'],
			["PDWORD", "entriesread",'out'],
			["PDWORD", "totalentries",'out'],
			["DWORD", "resume_handle",'inout']
		])

		dll.add_function('NetApiBufferFree', 'LPVOID',[
			["LPVOID","Buffer","in"],
		])


		dll.add_function('NetServerEnum', 'DWORD',[
			["PWCHAR","servername","in"],
			["DWORD","level","in"],
			["PDWORD","bufptr","out"],
			["DWORD","prefmaxlen","in"],
			["PDWORD","entriesread","out"],
			["PDWORD","totalentries","out"],
			["DWORD","servertype","in"],
			["PWCHAR","domain","in"],
			["DWORD","resume_handle","inout"]
		])

		return dll
	end

end

end; end; end; end; end; end; end


