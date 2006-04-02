module Msf

###
#
# The states that a host can be in.
#
###
module HostState
	#
	# The host is alive.
	#
	Alive   = "alive"
	#
	# The host is dead.
	#
	Dead    = "down"
	#
	# The host state is unknown.
	#
	Unknown = "unknown"
end

###
#
# The states that a service can be in.
#
###
module ServiceState
	#
	# The service is alive.
	#
	Up      = "up"
	#
	# The service is dead.
	#
	Dead    = "down"
	#
	# The service state is unknown.
	#
	Unknown = "unknown"
end


###
#
# The DB module ActiveRecord definitions for the DBManager
#
###

class DBManager

	#
	# Reports a host as being in a given state by address.
	#
	def report_host_state(mod, addr, state, context = nil)

		# TODO: use the current thread's Comm to find the host
		comm = ''
		host = get_host(context, addr, comm)
		
		ostate = host.state
		host.state = state
		host.save
		
		framework.events.on_db_host_state(context, host, ostate)
		return host
	end

	#
	# This method reports a host's service state.
	#
	def report_service_state(mod, addr, proto, port, state, context = nil)
		
		# TODO: use the current thread's Comm to find the host
		comm = ''
		host = get_host(context, addr, comm)
		port = get_service(context, host, proto, port)
		
		ostate = port.state
		port.state = state
		port.save
		
		framework.events.on_db_service_state(context, host, port, ostate)
		return port
	end
	

	#
	# This method iterates the hosts table calling the supplied block with the
	# host instance of each entry.
	# TODO: use the find() block syntax instead
	#
	def each_host(&block)
		hosts.each do |host|
			block.call(host)
		end
	end

	#
	# This methods returns a list of all hosts in the database
	#
	def hosts
		Host.find(:all)
	end

	#
	# This method iterates the services table calling the supplied block with the
	# service instance of each entry.
	#
	def each_service(&block)
		services.each do |service|
			block.call(service)
		end
	end
	
	#
	# This methods returns a list of all services in the database
	#
	def services
		Service.find(:all)
	end

	#
	# This method iterates the vulns table calling the supplied block with the
	# vuln instance of each entry.
	#
	def each_vuln(&block)
		vulns.each do |vulns|
			block.call(vulns)
		end
	end
	
	#
	# This methods returns a list of all vulnerabilities in the database
	#
	def vulns
		Vuln.find(:all)
	end
		
	def get_host(context, address, comm='')
		host = Host.find(:first, :conditions => [ "address = ? and comm = ?", address, comm])
		if (not host)
			host = Host.create(:address => address, :comm => comm, :state => HostState::Unknown)
			framework.events.on_db_host(context, host)
		end

		return host
	end
	
	def get_service(context, host, proto, port)
		rec = Service.find(:first, :conditions => [ "host_id = ? and proto = ? and port = ?", host.id, proto, port])
		if (not rec)
			rec = Service.create(
				:host_id    => host.id,
				:proto      => proto,
				:port       => port,
				:state      => ServiceState::Up
			)
			framework.events.on_db_service(context, rec)
		end
		return rec
	end

	def get_vuln(context, service, name, data='')
		vuln = Vuln.find(:first, :conditions => [ "name = ? and service_id = ?", name, service.id])
		if (not vuln)
			vuln= Vuln.create(
				:service_id => service.id,
				:name       => name,
				:data       => data
			)
			framework.events.on_db_vuln(context, vuln)
		end

		return vuln
	end
		
	def has_host?(addr)
		Host.find(:first, :conditions => [ "address = ?", addr])
	end
	
end

end
