# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_netapi32

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa371109.aspx
	USER_INFO_1 = [
		[:usri1_name, :LPWSTR],
		[:usri1_password, :LPWSTR],
		[:usri1_password_age, :DWORD],
		[:usri1_priv, :DWORD],
		[:usri1_home_dir, :LPWSTR],
		[:usri1_comment, :LPWSTR],
		[:usri1_flags, :DWORD],
		[:usri1_script_path, :LPWSTR]
	]

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370897.aspx
	SERVER_INFO_100 = [
		[:sv100_platform_id, :DWORD],
		[:sv100_name, :LPWSTR]
	]

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370903.aspx
	SERVER_INFO_101 = [
		[:sv101_platform_id, :DWORD],
		[:sv101_name, :LPWSTR],
		[:sv101_version_major, :DWORD],
		[:sv101_version_minor, :DWORD],
		[:sv101_type, :DWORD],
		[:sv101_comment, :LPWSTR]
	]

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370247.aspx
	AT_ENUM = [
		[:JobId, :DWORD],
		[:JobTime, :PDWORD_PTR],
		[:DaysOfMonth, :DWORD],
		[:DaysOfWeek, :UCHAR],
		[:Flags, :UCHAR],
		[:Command, :LPWSTR]
	]

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370248.aspx
	AT_INFO = [
		[:JobTime, :PDWORD_PTR],
		[:DaysOfMonth, :DWORD],
		[:DaysOfWeek, :UCHAR],
		[:Flags, :UCHAR],
		[:Command, :LPWSTR]
	]

	def self.create_dll(dll_path = 'netapi32')
		dll = DLL.new(dll_path, ApiConstants.manager)

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370649.aspx
		dll.add_function('NetUserAdd', 'DWORD',[
			["PWCHAR","servername","in"],
			["DWORD","level","in"], # 1, 2, 3, 4
			["PBLOB","buf","in"], # ptr to USER_INFO_x structure where x = +level+
			["PDWORD","parm_err","out"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370650.aspx
		dll.add_function('NetUserChangePassword', 'DWORD',[
			["PWCHAR","domainname","in"],
			["PWCHAR","username","in"],
			["PWCHAR","oldpassword","in"],
			["PWCHAR","newpassword","in"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370651.aspx
		dll.add_function('NetUserDel', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","username","in"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370652.aspx
		dll.add_function('NetUserEnum', 'DWORD',[
			["PWCHAR","servername","in"],
			["DWORD","level","in"], # 0, 1, 2, 3, 4, 10, 11, 20, 23
			["DWORD","filter","in"],
			["PDWORD","bufptr","out"], # ptr to array of USER_INFO_x structures where x = +level+
			["DWORD","prefmaxlen","in"],
			["PDWORD","entriesread","out"],
			["PDWORD","totalentries","out"],
			["DWORD","resume_handle","inout"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370423.aspx
		dll.add_function('NetGetJoinInformation', 'DWORD',[
			["PWCHAR","lpServer","in"],
			["PDWORD","lpNameBuffer","out"],
			["PDWORD","BufferType","out"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370623.aspx
		dll.add_function('NetServerEnum', 'DWORD',[
			["PWCHAR","servername","in"],
			["DWORD","level","in"], # 100, 101
			["PDWORD","bufptr","out"], # ptr to array of SERVER_INFO_x structures where x = +level+
			["DWORD","prefmaxlen","in"],
			["PDWORD","entriesread","out"],
			["PDWORD","totalentries","out"],
			["DWORD","servertype","in"],
			["PWCHAR","domain","in"],
			["DWORD","resume_handle","inout"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370304.aspx
		dll.add_function('NetApiBufferFree', 'DWORD',[
			["LPVOID","Buffer","in"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370426.aspx
		dll.add_function('NetGroupDel', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","groupname","in"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370428.aspx
		dll.add_function('NetGroupEnum', 'DWORD',[
			["PWCHAR","servername","in"],
			["DWORD","level","in"], # 0, 1, 2, 3
			["PDWORD","bufptr","out"], # ptr to array of GROUP_INFO_x structures where x = +level+
			["DWORD","prefmaxlen","in"],
			["PDWORD","entriesread","out"],
			["PDWORD","totalentries","out"],
			["DWORD","resume_handle","inout"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370437.aspx
		dll.add_function('NetLocalGroupDel', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","groupname","in"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370440.aspx
		dll.add_function('NetLocalGroupEnum', 'DWORD',[
			["PWCHAR","servername","in"],
			["DWORD","level","in"], # 0, 1
			["PDWORD","bufptr","out"], # ptr to array of LOCALGROUP_INFO_x structures where x = +level+
			["DWORD","prefmaxlen","in"],
			["PDWORD","entriesread","out"],
			["PDWORD","totalentries","out"],
			["DWORD","resumehandle","inout"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370614.aspx
		dll.add_function('NetScheduleJobAdd', 'DWORD',[
			["PWCHAR","Servername","in"],
			["PBLOB","Buffer","in"], # ptr to AT_INFO structure
			["PDWORD","JobId","out"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370615.aspx
		dll.add_function('NetScheduleJobDel', 'DWORD',[
			["PWCHAR","Servername","in"],
			["DWORD","MinJobId","in"],
			["DWORD","MaxJobId","in"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370616.aspx
		dll.add_function('NetScheduleJobEnum', 'DWORD',[
			["PWCHAR","Servername","in"],
			["PDWORD","PointerToBuffer","out"], # ptr to array of AT_ENUM structures
			["DWORD","PreferredMaximumLength","in"],
			["PDWORD","EntriesRead","out"],
			["PDWORD","TotalEntries","out"],
			["DWORD","ResumeHandle","inout"]
		])

		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370617.aspx
		dll.add_function('NetScheduleJobGetInfo', 'DWORD',[
			["PWCHAR","Servername","in"],
			["DWORD","JobId","in"],
			["PBLOB","PointerToBuffer","out"] # ptr to AT_INFO structure
		])

		return dll
	end

end

end; end; end; end; end; end; end
