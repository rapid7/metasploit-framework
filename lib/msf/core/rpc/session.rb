module Msf
module RPC
class Session < Base

	def list(token)
		authenticate(token)
		res = {}
		@framework.sessions.each do |sess|
			i,s = sess
			res[s.sid] = { 
				'type'        => s.type,
				'tunnel_local'=> s.tunnel_local,
				'tunnel_peer' => s.tunnel_peer,
				'via_exploit' => s.via_exploit,
				'via_payload' => s.via_payload,
				'desc'        => s.desc
			}
		end
		res
	end
	
	def stop(token, sid)
		authenticate(token)
		s = _find_session(sid)
		s.kill
		{ "result" => "success" }
	end
	
	def shell_read(token, sid)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "shell")
			raise ::XMLRPC::FaultException.new(403, "session is not a shell")
		end
		
		if(not s.rstream.has_read_data?(0))
			{ "data" => "" }
		else
			{ "data" => s.read_shell }
		end
	end
	
	def shell_write(token, sid, data)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "shell")
			raise ::XMLRPC::FaultException.new(403, "session is not a shell")
		end
		
		{ "write_count" => s.write_shell(data) }
	end
	
protected

	def _find_session(sid)
		s = @framework.sessions[sid.to_i]
		if(not s)
			raise ::XMLRPC::FaultException.new(404, "unknown session")
		end
		s
	end

end
end
end
