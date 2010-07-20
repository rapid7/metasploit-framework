module Msf
module RPC
class Core < Base

	def version(token)
		authenticate(token)
		{ "version" => ::Msf::Framework::Version }
	end

end
end
end
