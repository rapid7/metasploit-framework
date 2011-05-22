module Msf
module RPC
class RPC_Core < RPC_Base

	def rpc_version
		{
			"version" => ::Msf::Framework::Version, 
			"ruby"    => "#{RUBY_VERSION} #{RUBY_PLATFORM} #{RUBY_RELEASE_DATE}",
			"api"     => API_VERSION 
		}
	end
	
	def rpc_stop
		self.service.stop
	end
end
end
end
