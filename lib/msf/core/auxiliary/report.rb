module Msf

###
#
# This module provides methods for reporting data to the DB
#
###

module Auxiliary::Report

# 
# Report host and service information
#
			
	# Shortcut method for detecting when the DB is active
	def db
		framework.db.active
	end
	
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

	def report_note(opts={})
		return if not db
		addr  = opts[:host]  || return
		ntype = opts[:type]  || return
		data  = opts[:data]  || return

		host  = framework.db.report_host_state(self, addr, Msf::HostState::Alive)
		note  = framework.db.get_note(self, host, ntype, data)
	end

	def report_auth_info(opts={})		
		addr  = opts[:host]   || return
		data  = opts[:proto]  || return
		
		opts[:type] = "auth_#{opts[:proto]}"
		opts[:data] = 
			"AUTH #{ opts[:targ_host] || 'unknown' }:#{ opts[:targ_port] || 'unknown' } " +
			"#{opts[:user] || "<NULL>"} #{opts[:pass] || "<NULL>" } #{opts[:extra]}"
		report_note(opts)	
	end


end
end
