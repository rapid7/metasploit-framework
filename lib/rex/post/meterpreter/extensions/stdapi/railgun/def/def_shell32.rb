module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_shell32

	def self.add_imports(railgun)
		
		railgun.add_dll('shell32')

		railgun.add_function( 'shell32', 'IsUserAnAdmin', 'BOOL', [
			])
	end
	
end

end; end; end; end; end; end; end
