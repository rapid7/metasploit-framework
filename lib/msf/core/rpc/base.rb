module Msf
module RPC
class Base

	def initialize(framework,tokens,users)
		@framework = framework
		@tokens    = tokens
		@users     = users
	end

	def authenticate(token)
	
		stale = []
		@tokens.each_key do |t|
			user,ctime,mtime = @tokens[t]
			if(mtime + 300 < Time.now.to_i)
				stale << t
			end
		end
		
		stale.each { |t| @tokens.delete(t) }
	
		if(not @tokens[token])
			raise ::XMLRPC::FaultException.new(401, "authentication error")
		end
		
		@tokens[token][2] = Time.now.to_i
	end


end
end
end
