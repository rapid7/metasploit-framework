module Msf
module RPC
class Core < Base

	def initialize(framework, tokens, users, server=nil)
		@server = server
		super(framework, tokens, users)
	end

	def version(token)
		authenticate(token)
		{ "version" => ::Msf::Framework::Version }
	end

	#
	# Stop the RPC server.  This method will never return a value to the client
	# because the socket for communicating with it will be closed.
	#
	def stop(token)
		authenticate(token)
		@server.stop_rpc if @server
		nil
	end

end
end
end
