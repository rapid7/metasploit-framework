module Msf
module RPC
class RPC_Auth < RPC_Base

	def rpc_login_noauth(user,pass)
	
		# handle authentication here
		fail = true
		self.users.each do |u|
			if(u[0] == user and u[1] == pass)
				fail = false
				break
			end
		end
	
		error(401, "Login Failed") if fail
		
		token = "TEMP" + Rex::Text.rand_text_alphanumeric(28)
		self.tokens[token] = [user, Time.now.to_i, Time.now.to_i]
		{ "result" => "success", "token" => token }
	end
	
	def rpc_logout
		# Delete the token if its not marked as permanent
		found = self.tokens[token]
		if found and found[3] != true
			self.tokens.delete(token)
		end
		{ "result" => "success" }
	end

end
end
end
