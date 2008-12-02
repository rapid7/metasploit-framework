module Msf
module RPC
class Auth < Base

	def login(user,pass)
	
		# handle authentication here
		fail = true
		@users.each do |u|
			if(u[0] == user and u[1] == pass)
				fail = false
				break
			end
		end
	
		if(fail)
			raise ::XMLRPC::FaultException.new(401, "authentication error")
		end
		
		token = Rex::Text.rand_text_alphanumeric(32)
		@tokens[token] = [user, Time.now.to_i, Time.now.to_i]
		{ "result" => "success", "token" => token }
	end
	
	def logout(token)
		@tokens.delete(token)
		{ "result" => "success" }
	end

end
end
end
