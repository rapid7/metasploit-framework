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
	def info(token,jid)
		authenticate(token)
		obj = @framework.jobs[jid.to_s]
		if(not obj)
			raise ::XMLRPC::FaultException.new(404, "no such job")
		else
			info = {
				"jid"  => obj.jid,
				"name" => obj.name,
				"start_time" => obj.start_time.to_i
			}
			if obj.ctx && obj.ctx[0]
				if obj.ctx[0].respond_to?(:get_resource)
					info['uripath'] = obj.ctx[0].get_resource
				end
				if obj.ctx[0].respond_to?(:datastore)
					info['datastore'] = obj.ctx[0].datastore
				end
			end
			{ "result" => "success" , "info" => info}
		end
	end
end
end
end
