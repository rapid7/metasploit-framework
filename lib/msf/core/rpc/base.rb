module Msf
module RPC
class Base

	def initialize(framework,tokens,users,plugin)
		@framework = framework
		@tokens    = tokens
		@users     = users
		@plugin    = plugin
	end

	def authenticate(token)

		stale = []
		@tokens.each_key do |t|
			user,ctime,mtime,perm = @tokens[t]
			if ! perm and mtime + 300 < Time.now.to_i
				stale << t
			end
		end

		stale.each { |t| @tokens.delete(t) }

		if(not @tokens[token])
			raise ::XMLRPC::FaultException.new(401, "authentication error")
		end

		@tokens[token][2] = Time.now.to_i
	end


	def stop(token)
		authenticate(token)
		@plugin.cleanup
	end

end
end
end

