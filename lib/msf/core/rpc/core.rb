module Msf
module RPC
class Core < Base

	def version(token)
		authenticate(token)
		{ "version" => ::Msf::Framework::Version }
	end

	def stop(token)
		authenticate(token)
		@plugin.cleanup
	end

end
end
end
