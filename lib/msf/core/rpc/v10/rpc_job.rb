module Msf
module RPC
class RPC_Job < RPC_Base

	def rpc_list
		res = { 'result' => 'success', 'jobs' => {} }
		self.framework.jobs.each do |j|
			 res['jobs'][j[0]] = j[1].name
		end
		res
	end
	
	def rpc_stop(jid)
		obj = self.framework.jobs[jid.to_s]
		if(not obj)
			error(500, "Invalid Job")
		else
			obj.stop
			{ "result" => "success" }
		end
	end
	
	def rpc_info(jid)
		obj = self.framework.jobs[jid.to_s]
		if(not obj)
			error(500, "Invalid Job")
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
