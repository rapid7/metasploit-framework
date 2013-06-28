# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_psapi

	def self.create_dll(dll_path = 'psapi')
		dll = DLL.new(dll_path, ApiConstants.manager)

		dll.add_function('EnumDeviceDrivers', 'BOOL',
			[
				["PBLOB", "lpImageBase", "out"],
				["DWORD", "cb", "in"],
				["PDWORD", "lpcbNeeded", "out"]
			])

		dll.add_function('GetDeviceDriverBaseNameA', 'DWORD',
			[
				["LPVOID", "ImageBase", "in"],
				["PBLOB", "lpBaseName", "out"],
				["DWORD", "nSize", "in"]
			])

		return dll
	end

end

end; end; end; end; end; end; end


