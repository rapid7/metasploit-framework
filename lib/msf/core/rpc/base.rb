module Msf
module RPC
class Base

	def initialize(framework,tokens,users)
		@framework = framework
		@tokens    = tokens
		@users     = users
	end

private

	def authenticate(token)
		stale = []

		# Force the encoding to ASCII-8BIT
		token = token.unpack("C*").pack("C*")

		@tokens.each_key do |t|
			user,ctime,mtime,perm = @tokens[t]
			if ! perm and mtime + 300 < Time.now.to_i
				stale << t
			end
		end

		stale.each { |t| @tokens.delete(t) }

		if not @tokens[token]
			raise ::XMLRPC::FaultException.new(401, "authentication error")
		end

		@tokens[token][2] = Time.now.to_i
	end

end
end
end

