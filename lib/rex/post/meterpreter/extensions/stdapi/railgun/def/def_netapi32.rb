module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_netapi32

	def self.create_dll(dll_path = 'netapi32')
		dll = DLL.new(dll_path, ApiConstants.manager)

		dll.add_function('NetUserDel', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","username","in"],
			])

		dll.add_function('NetGetJoinInformation', 'DWORD',[
			["PBLOB","lpServer","in"],
			["PDWORD","lpNameBugger","out"],
			["PDWORD","BufferType","out"]
			])

		return dll
	end

end

end; end; end; end; end; end; end


