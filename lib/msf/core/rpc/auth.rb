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
	
		if fail
			# Introduce a random delay in the response to annoy brute forcers
			delay = [ ( rand(3000) / 1000.0 ), 0.50 ].max
			::IO.select(nil, nil, nil, delay)
			
			# Send back a 401 denied error
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
