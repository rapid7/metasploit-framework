module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_netapi32

	def self.add_imports(railgun)
		
		railgun.add_dll('netapi32')

		railgun.add_function( 'netapi32', 'NetUserDel', 'DWORD',[
			["PWCHAR","servername","in"],
			["PWCHAR","username","in"],
			])

	end
	
end

end; end; end; end; end; end; end


