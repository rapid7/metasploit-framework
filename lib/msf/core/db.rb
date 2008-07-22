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
# Events that can occur in the host/service database.
#
###
module DatabaseEvent

	#
	# Called when an existing host's state changes
	#
	def on_db_host_state(context, host, ostate)
	end

	#
	# Called when an existing service's state changes
	#
	def on_db_service_state(context, host, port, ostate)
	end

	#
	# Called when a new host is added to the database.  The host parameter is
	# of type Host.
	#
	def on_db_host(context, host)
	end

	#
	# Called when a new service is added to the database.  The service
	# parameter is of type Service.
	#
	def on_db_service(context, service)
	end

	#
	# Called when an applicable vulnerability is found for a service.  The vuln
	# parameter is of type Vuln.
	#
	def on_db_vuln(context, vuln)
	end

	#
	# Called when a new reference is created.
	#
	def on_db_ref(context, ref)
	end

end

###
#
# The DB module ActiveRecord definitions for the DBManager
#
###
class DBManager


	#
	# Determines if the database is functional
	#
	def check
		res = Host.find(:all)
	end

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
	# Report a host's attributes such as operating system and service pack
	#
	# At the time of this writing, the opts parameter can contain:
	#	:state       -- one of the Msf::HostState constants
	#	:os_name     -- one of the Msf::Auxiliary::Report::OperatingSystems constants
	#	:os_flavor   -- something like "XP" or "Gentoo"
	#	:os_sp       -- something like "SP2"
	#	:os_lang     -- something like "English" or "French"
	#	:arch        -- one of the ARCH_* constants
	#
	# See <MSF install dir>/data/sql/*.sql for more info
	#
	def report_host(mod, addr, opts = {}, context = nil)

		report_host_state(mod, addr, opts[:state] || Msf::HostState::Alive)
		opts.delete(:state)
		
		host = get_host(context, addr, '')
		
		opts.each { |k,v|
			if (host.attribute_names.include?(k.to_s))
				host[k] = v
			end
		}

		host.save 
		
		return host
	end

	#
	# This method reports a host's service state.
	#
	def report_service_state(mod, addr, proto, port, state, context = nil)
		
		# TODO: use the current thread's Comm to find the host
		comm = ''
		host = get_host(context, addr, comm)
		port = get_service(context, host, proto, port, state)
		
		ostate = port.state
		port.state = state
		port.save
		
		if (ostate != state)
			framework.events.on_db_service_state(context, host, port, ostate)
		end
		
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


	#
	# This method iterates the notes table calling the supplied block with the
	# note instance of each entry.
	#
	def each_note(&block)
		notes.each do |note|
			block.call(note)
		end
	end
	
	#
	# This methods returns a list of all notes in the database
	#
	def notes
		Note.find(:all)
	end
		
	#
	# Find or create a host matching this address/comm
	#
	def get_host(context, address, comm='')
		host = Host.find(:first, :conditions => [ "address = ? and comm = ?", address, comm])
		if (not host)
			host = Host.create(:address => address, :comm => comm, :state => HostState::Unknown, :created => Time.now)
			host.save
			framework.events.on_db_host(context, host)
		end

		return host
	end

	#
	# Find or create a service matching this host/proto/port/state
	#	
	def get_service(context, host, proto, port, state=ServiceState::Up)
		rec = Service.find(:first, :conditions => [ "host_id = ? and proto = ? and port = ?", host.id, proto, port])
		if (not rec)
			rec = Service.create(
				:host_id    => host.id,
				:proto      => proto,
				:port       => port,
				:state      => state,
				:created    => Time.now
			)
			rec.save
			framework.events.on_db_service(context, rec)
		end
		return rec
	end

	#
	# Find or create a vuln matching this service/name
	#	
	def get_vuln(context, service, name, data='')
		vuln = Vuln.find(:first, :conditions => [ "name = ? and service_id = ?", name, service.id])
		if (not vuln)
			vuln = Vuln.create(
				:service_id => service.id,
				:name       => name,
				:data       => data,
				:created    => Time.now
			)
			vuln.save
			framework.events.on_db_vuln(context, vuln)
		end

		return vuln
	end

	#
	# Find or create a reference matching this name
	#
	def get_ref(context, name)
		ref = Ref.find(:first, :conditions => [ "name = ?", name])
		if (not ref)
			ref = Ref.create(
				:name       => name,
				:created    => Time.now
			)
			ref.save
			framework.events.on_db_ref(context, ref)
		end

		return ref
	end

	#
	# Find or create a note matching this type/data
	#	
	def get_note(context, host, ntype, data)
		rec = Note.find(:first, :conditions => [ "host_id = ? and ntype = ? and data = ?", host.id, ntype, data])
		if (not rec)
			rec = Note.create(
				:host_id    => host.id,
				:ntype      => ntype,
				:data       => data,
				:created    => Time.now
			)
			rec.save
			framework.events.on_db_note(context, rec)
		end
		return rec
	end
	
	#
	# Find a reference matching this name
	#
	def has_ref?(name)
		Ref.find(:first, :conditions => [ "name = ?", name])
	end

	#
	# Find a vulnerability matching this name
	#
	def has_vuln?(name)
		Vuln.find(:first, :conditions => [ "name = ?", name])
	end
		
	#
	# Look for an address across all comms
	#			
	def has_host?(addr)
		Host.find(:first, :conditions => [ "address = ?", addr])
	end

	#
	# Find all references matching a vuln
	#		
	def refs_by_vuln(vuln)
		Ref.find_by_sql(
			"SELECT refs.* FROM refs, vulns_refs WHERE " +
			"vulns_refs.vuln_id = #{vuln.id} AND " +
			"vulns_refs.ref_id = refs.id"
		)
	end	
	
	#
	# Find all vulns matching a reference
	#		
	def vulns_by_ref(ref)
		Vuln.find_by_sql(
			"SELECT vulns.* FROM vulns, vulns_refs WHERE " +
			"vulns_refs.ref_id = #{ref.id} AND " +
			"vulns_refs.vuln_id = vulns.id"
		)
	end	

									
end

end
