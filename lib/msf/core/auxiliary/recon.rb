module Msf

###
#
# This module provides methods for reporting information
#
###

module Auxiliary::Recon

	def report_host(opts)
		return if not db
		addr = opts[:host] || return
		framework.db.report_host_state(self, addr, Msf::HostState::Alive)
	end

	def report_service(opts={})
		return if not db
		addr  = opts[:host]  || return
		port  = opts[:port]  || return
		proto = opts[:proto] || 'tcp'
		name  = opts[:name]
		state = opts[:state] || Msf::ServiceState::Up
		
		framework.db.report_host_state(self, addr, Msf::HostState::Alive)
		
		serv = framework.db.report_service_state(
			self,
			addr,
			proto,
			port,
			state
		)
		if (name and name.length > 1)
			serv.name = name
			serv.save!
		end
	end
		
	# Shortcut method for detecting when the DB is active
	def db
		framework.db.active
	end

end
end
