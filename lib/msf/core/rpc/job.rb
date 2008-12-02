module Msf
module RPC
class Job < Base

	def list(token)
		authenticate(token)
		res         = {}
		res['jobs'] = {}
		@framework.jobs.each do |j|
			 res['jobs'][j[0]] = j[1].name
		end
		res
	end
	
	def stop(token,jid)
		authenticate(token)
		obj = @framework.jobs[jid.to_s]
		if(not obj)
			raise ::XMLRPC::FaultException.new(404, "no such job")
		else
			obj.stop
			{ "result" => "success" }
		end
	end
end
end
end
