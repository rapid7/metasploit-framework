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
	
	def rpc_logout(token)
		# Delete the token if its not marked as permanent
		found = self.tokens[token]
		if found and found[3] != true
			self.tokens.delete(token)
		end
		{ "result" => "success" }
	end
	
	def rpc_token_list
		res = self.service.tokens.keys
		begin
			if framework.db and framework.db.active
				Msf::DBManager::ApiKey.find(:all).each do |k|
					res << k.token
				end
			end
		rescue ::Exception
		end
		{ "tokens" => res }
	end

	def rpc_token_add(token)
		db = false
		begin
			if framework.db and framework.db.active
				t = Msf::DBManager::ApiKey.new
				t.token = token
				t.save!
				db = true
			end
		rescue ::Exception
		end
		
		if not db
			self.service.tokens[token] = [nil, nil, nil, true]
		end
		
		{ "result" => "success" }
	end
	
	def rpc_token_generate
		token = Rex::Text.rand_text_alphanumeric(32)
		db = false
		begin
			if framework.db and framework.db.active
				t = Msf::DBManager::ApiKey.new
				t.token = token
				t.save!
				db = true
			end
		rescue ::Exception
		end
		
		if not db
			token = "TEMP" + Rex::Text.rand_text_alphanumeric(28)
			self.service.tokens[token] = [nil, nil, nil, true]
		end
		
		{ "result" => "success", "token" => token }
	end
	
	def rpc_token_remove(token)
		db = false
		begin
			if framework.db and framework.db.active
				t = Msf::DBManager::ApiKey.find_by_token(token)
				t.destroy if t
				db = true
			end
		rescue ::Exception
		end
		
		self.service.tokens.delete(token)
		
		{ "result" => "success" }	
	end
	
end
end
end
