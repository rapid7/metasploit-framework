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
	def on_db_host_state(host, ostate)
	end

	#
	# Called when an existing service's state changes
	#
	def on_db_service_state(host, port, ostate)
	end

	#
	# Called when a new host is added to the database.  The host parameter is
	# of type Host.
	#
	def on_db_host(host)
	end

	#
	# Called when a new client is added to the database.  The client
	# parameter is of type Client.
	#
	def on_db_client(client)
	end

	#
	# Called when a new service is added to the database.  The service
	# parameter is of type Service.
	#
	def on_db_service(service)
	end

	#
	# Called when an applicable vulnerability is found for a service.  The vuln
	# parameter is of type Vuln.
	#
	def on_db_vuln(vuln)
	end

	#
	# Called when a new reference is created.
	#
	def on_db_ref(ref)
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


	def default_workspace
		Workspace.default
	end

	def find_workspace(name)
		Workspace.find_by_name(name)
	end

	#
	# Creates a new workspace in the database
	#
	def add_workspace(name)
		Workspace.find_or_create_by_name(name)
	end

	def workspaces
		Workspace.find(:all)
	end


	# 
	# Find a host.  Performs no database writes.
	#
	def get_host(opts)
		if opts.kind_of? Host
			return opts
		elsif opts.kind_of? String
			address = opts
		else
			address = opts[:addr] || opts[:address] || opts[:host] || return
			return address if address.kind_of? Host
		end
		host = workspace.hosts.find_by_address(address)
		return host
	end

	def find_or_initialize_host(opts)
		addr = opts.delete(:host) || return
		return addr if addr.kind_of? Host

		#if opts[:comm] and opts[:comm].length > 0
		#	host = workspace.hosts.find_or_initialize_by_address_and_comm(addr, opts[:comm])
		#else
			host = workspace.hosts.find_or_initialize_by_address(addr)
		#end

		opts.each { |k,v|
			if (host.attribute_names.include?(k.to_s))
				host[k] = v
			else
				dlog("Unknown attribute for Host: #{k}")
			end
		}
		host.state     = HostState::Unknown if not host.state
		host.comm      = ''        if not host.comm
		host.workspace = workspace if not host.workspace

		return host
	end

	# 
	# Exactly like report_host but ensures that the returned Host has been
	# written to the database.  Returns nil on error.
	#
	def find_or_create_host(opts)
		host = find_or_initialize_host(opts)
		
		if (host and host.changed?)
			host.created = Time.now
			task = framework.db.queue( Proc.new { host.save! } )
			task.wait
			if task.status != :done
				return nil
			end
		end
		return host
	end

	#
	# Report a host's attributes such as operating system and service pack
	#
	# The opts parameter MUST contain
	#	:address    -- the host's ip address
	#
	# The opts parameter can contain:
	#	:state      -- one of the Msf::HostState constants
	#	:os_name    -- one of the Msf::OperatingSystems constants
	#	:os_flavor  -- something like "XP" or "Gentoo"
	#	:os_sp      -- something like "SP2"
	#	:os_lang    -- something like "English" or "French"
	#	:arch       -- one of the ARCH_* constants
	#	:mac        -- the host's MAC address
	#
	# Returns a Host that may not have been written to the database yet.
	# If you need to be sure that the insert succeeded, use
	# find_or_create_host.
	#
	def report_host(opts)
		host = find_or_initialize_host(opts)
		if (host.changed?)
			host.created = Time.now
			framework.db.queue( Proc.new { host.save! } )
		end
		return host
	end

	#
	# Iterates over the hosts table calling the supplied block with the host
	# instance of each entry.
	#
	def each_host(&block)
		workspace.hosts.each do |host|
			block.call(host)
		end
	end

	#
	# Returns a list of all hosts in the database
	#
	def hosts(only_up = false, addresses = nil)
		conditions = {}
		conditions[:state] = [Msf::HostState::Alive, Msf::HostState::Unknown] if only_up
		conditions[:address] = addresses if addresses
		workspace.hosts.all(:conditions => conditions, :order => :address)
	end



	def find_or_initialize_service(opts)
		addr = opts.delete(:host) || return
		host = find_or_create_host({:host => addr})
		proto = opts[:proto] || 'tcp'
		service = host.services.find_or_initialize_by_port_and_proto(opts[:port], proto)
		opts.each { |k,v|
			if (service.attribute_names.include?(k.to_s))
				service[k] = v
			else
				dlog("Unknown attribute for Service: #{k}")
			end
		}
		return service
	end

	def find_or_create_service(opts)
		service = find_or_initialize_service(opts)
		if (service and service.changed?)
			service.created = Time.now
			task = framework.db.queue(Proc.new { service.save! })
			task.wait
			if task.status != :done
				return nil
			end
		end
		return service
	end

	# 
	# Record a service in the database.  
	#
	# opts must contain
	#	:host  -- the host where this service is running
	#	:port  -- the port where this service listens
	#	:proto -- the protocol (e.g. tcp, udp...)
	#
	# Returns a Service.  Not guaranteed to have been written to the db yet.
	# If you need to be sure that the insert succeeded, use
	# find_or_create_service.
	#
	def report_service(opts)
		service = find_or_initialize_service(opts)
		if (service and service.changed?)
			service.created = Time.now
			framework.db.queue(Proc.new { service.save! })
		end
		return service
	end

	def get_service(host, proto, port)
		host = get_host(host)
		return if not host
		return host.services.find_by_proto_and_port(proto, port)
	end

	#
	# Iterates over the services table calling the supplied block with the
	# service instance of each entry.
	#
	def each_service(&block)
		services.each do |service|
			block.call(service)
		end
	end

	#
	# Returns a list of all services in the database
	#
	def services(only_up = false, proto = nil, addresses = nil, ports = nil, names = nil)
		conditions = {}
		conditions[:state] = ['open'] if only_up
		conditions[:proto] = proto if proto
		conditions["hosts.address"] = addresses if addresses
		conditions[:port] = ports if ports
		conditions[:name] = names if names
		workspace.services.all(:include => :host, :conditions => conditions, :order => "hosts.address, port")
	end


	def get_client(opts)
		host = get_host(:host => opts[:host]) || return
		client = host.clients.find(:first, :conditions => {:ua_string => opts[:ua_string]})
		return client
	end

	def find_or_initialize_client(opts)
		host = find_or_create_host(:host => opts.delete(:host))
		return if not host
		client = host.clients.find_or_initialize_by_ua_string(opts[:ua_string])
		opts.each { |k,v|
			if (client.attribute_names.include?(k.to_s))
				client[k] = v
			else
				dlog("Unknown attribute for Client: #{k}")
			end
		}
		return client
	end

	def find_or_create_client(opts)
		client = find_or_initialize_client(opts)
		
		if (client and client.changed?)
			client.created = Time.now
			task = framework.db.queue(Proc.new { client.save! })
			task.wait
			if task.status != :done
				return nil
			end
		end

		return client
	end

	#
	# Report a client running on a host.
	#
	# opts must contain 
	#   :ua_string  -- the value of the User-Agent header
	#
	# opts can contain 
	#   :ua_name    -- one of the Msf::HttpClients constants
	#   :ua_ver     -- detected version of the given client
	#
	# Returns a Client.  Not guaranteed to have been written to the database.
	# If you need to be sure that the insert succeeded, use
	# find_or_create_client.
	#
	def report_client(opts)
		client = find_or_initialize_client(opts)
		if (client and client.changed?)
			client.created = Time.now
			framework.db.queue(Proc.new { client.save! })
		end

		return client
	end

	#
	# This method iterates the vulns table calling the supplied block with the
	# vuln instance of each entry.
	#
	def each_vuln(&block)
		workspace.vulns.each do |vulns|
			block.call(vulns)
		end
	end

	#
	# This methods returns a list of all vulnerabilities in the database
	#
	def vulns
		workspace.vulns
	end

	#
	# This method iterates the notes table calling the supplied block with the
	# note instance of each entry.
	#
	def each_note(&block)
		workspace.notes.each do |note|
			block.call(note)
		end
	end

	#
	# Find or create a note matching this type/data
	#
	def find_or_create_note(opts)
		note = find_or_initialize_note(opts)
		if (note.changed?)
			note.created = Time.now
			task = framework.db.queue(Proc.new {note.save!})
			task.wait
			if (task.status != :done)
				return nil
			end
		end
		return note
	end

	def find_or_initialize_note(opts)
		ntype = opts.delete(:type) || opts.delete(:ntype) || return
		data  = opts[:data] || return

		note = workspace.notes.find_or_initialize_by_ntype_and_data(ntype, data.to_yaml)

		if opts[:host]
			if opts[:host].kind_of? Host
				host = opts[:host].dup
			else
				host = find_or_create_host({:host => opts[:host]})
			end
			note.host = host
		end
		if opts[:service] and opts[:service].kind_of? Service
			note.service = service
		end

		return note
	end

	def report_note(opts)
		note = find_or_initialize_note(opts)
		if (note and note.changed?)
			note.created = Time.now
			task = framework.db.queue(Proc.new {note.save!})
		end
		return note
	end

	#
	# This methods returns a list of all notes in the database
	#
	def notes
		workspace.notes
	end

	###
	# Specific notes
	###

	#
	# opts must contain
	#	:data    -- a hash containing the authentication info
	# 
	# opts can contain
	#	:host    -- an ip address or Host
	#	:service -- a Service
	#	:proto   -- the protocol
	#	:port    -- the port
	#
	def report_auth_info(opts={})
		return if not framework.db.active
		host    = opts.delete(:host)
		service = opts.delete(:service)
		proto   = opts.delete(:proto) || "generic"
		proto   = proto.downcase

		note = {
			:ntype => "auth:#{proto}",
			:host => host,
			:service => service,
			:data => opts
		}

		report_note(note)
	end

	def get_auth_info(opts={})
		return if not framework.db.active
		condition = ""
		condition_values = []
		if opts[:host]
			host = get_host(opts[:host])
			condition = "host_id == ?"
			condition_values = host.id
		end
		if opts[:proto]
			if condition.length > 0
				condition << " and "
			end
			condition << "ntype = ?"
			condition_values << "auth:#{opts[:proto].downcase}"
		else
			if condition.length > 0
				condition << " and "
			end
			condition << "ntype LIKE ?"
			condition_values << "auth:%"
		end
		conditions = [ condition ] + condition_values
		info = framework.db.notes.find(:all, :conditions => conditions )
		return info.map{|i| i.data} if info
	end



	#
	#
	#
	def find_or_initialize_vuln(opts)
		host  = find_or_create_host({:host => opts[:host]}) || return
		name  = opts[:name] || return
		data  = opts[:data]

		if data
			vuln = host.vulns.find_or_initialize_by_name_and_data(name, data)
		else
			vuln = host.vulns.find_or_initialize_by_name(name)
		end

		if opts[:service] and opts[:service].kind_of? Service
			vuln.service = opts[:service]
		end

		return vuln
	end

	#
	# Find or create a vuln matching this service/name
	#
	def find_or_create_vuln(opts)
		vuln = find_or_initialize_vuln(opts)
		if vuln and vuln.changed?
			vuln.created = Time.now
			task = framework.db.queue(Proc.new { vuln.save! })
			task.wait
			if task.status != :done
				return nil
			end
		end
		return vuln
	end

	#
	#
	#
	def report_vuln(opts)
		if vuln.changed?
			vuln.created = Time.now
			framework.db.queue(Proc.new { vuln.save! })
		end
		return vuln
	end

	def get_vuln(host, service, name, data='')
		vuln = nil
		if (service)
			vuln = Vuln.find(:first, :conditions => [ "name = ? and service_id = ? and host_id = ?", name, service.id, host.id])
		else
			vuln = Vuln.find(:first, :conditions => [ "name = ? and host_id = ?", name, host.id])
		end

		return vuln
	end

	#
	# Find or create a reference matching this name
	#
	def find_or_create_ref(opts)
		ref = Ref.find_or_initialize_by_name(opts[:name])
		if ref and ref.changed?
			ref.created = Time.now
			task = framework.db.queue(Proc.new { ref.save! })
			task.wait
			if task.status != :done
				return nil
			end
		end
		return ref
	end
	def get_ref(name)
		Ref.find_by_name(name)
	end


	#
	# Deletes a host and associated data matching this address/comm
	#
	def del_host(address, comm='')
		host = workspace.hosts.find_by_address_and_comm(address, comm)
		host.destroy if host
	end

	#
	# Deletes a port and associated vulns matching this port
	#
	def del_service(address, proto, port, comm='')
		host = get_host(address, comm)
		return unless host

		host.services.find(:all, :conditions => { :proto => proto, :port => port}).destroy_all
	end

	#
	# Find a reference matching this name
	#
	def has_ref?(name)
		Ref.find_by_name(name)
	end

	#
	# Find a vulnerability matching this name
	#
	def has_vuln?(name)
		Vuln.find_by_name(name)
	end

	#
	# Look for an address across all comms
	#
	def has_host?(addr)
		workspace.hosts.find_by_address(addr)
	end

	def vuln_add_refs(vuln, refs)
		return vuln if not refs
		rids = refs.map{|r| get_ref("#{r[0]}-#{r[1]}") }
		vuln.refs << rids
		vuln
	end

	#
	# WMAP
	# Support methods
	#

	#
	# WMAP
	# Selected host
	#
	def selected_host
		selhost = WmapTarget.find(:first, :conditions => ["selected != 0"] )
		if selhost
			return selhost.host
		else
			return
		end
	end

	#
	# WMAP
	# Selected port
	#
	def selected_port
		WmapTarget.find(:first, :conditions => ["selected != 0"] ).port
	end

	#
	# WMAP
	# Selected ssl
	#
	def selected_ssl
		WmapTarget.find(:first, :conditions => ["selected != 0"] ).ssl
	end

	#
	# WMAP
	# Selected id
	#
	def selected_id
		WmapTarget.find(:first, :conditions => ["selected != 0"] ).object_id
	end

	#
	# WMAP
	# This method iterates the requests table identifiying possible targets
	# This method wiil be remove on second phase of db merging.
	#
	def each_distinct_target(&block)
		request_distinct_targets.each do |target|
			block.call(target)
		end
	end

	#
	# WMAP
	# This method returns a list of all possible targets available in requests
	# This method wiil be remove on second phase of db merging.
	#
	def request_distinct_targets
		WmapRequest.find(:all, :select => 'DISTINCT host,address,port,ssl')
	end

	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_path(&block)
		target_requests('AND wmap_requests.path IS NOT NULL').each do |req|
			block.call(req)
		end
	end

	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_query(&block)
		target_requests('AND wmap_requests.query IS NOT NULL').each do |req|
			block.call(req)
		end
	end

	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_body(&block)
		target_requests('AND wmap_requests.body IS NOT NULL').each do |req|
			block.call(req)
		end
	end

	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_headers(&block)
		target_requests('AND wmap_requests.headers IS NOT NULL').each do |req|
			block.call(req)
		end
	end

	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target(&block)
		target_requests('').each do |req|
			block.call(req)
		end
	end

	#
	# WMAP
	# This method returns a list of all requests from target
	#
	def target_requests(extra_condition)
		WmapRequest.find(:all, :conditions => ["wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}",selected_host,selected_port])
	end

	#
	# WMAP
	# This method iterates the requests table calling the supplied block with the
	# request instance of each entry.
	#
	def each_request(&block)
		requests.each do |request|
			block.call(request)
		end
	end

	#
	# WMAP
	# This method allows to query directly the requests table. To be used mainly by modules
	#
	def request_sql(host,port,extra_condition)
		WmapRequest.find(:all, :conditions => ["wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}",host,port])
	end

	#
	# WMAP
	# This methods returns a list of all targets in the database
	#
	def requests
		WmapRequest.find(:all)
	end

	#
	# WMAP
	# This method iterates the targets table calling the supplied block with the
	# target instance of each entry.
	#
	def each_target(&block)
		targets.each do |target|
			block.call(target)
		end
	end

	#
	# WMAP
	# This methods returns a list of all targets in the database
	#
	def targets
		WmapTarget.find(:all)
	end

	#
	# WMAP
	# This methods deletes all targets from targets table in the database
	#
	def delete_all_targets
		WmapTarget.delete_all
	end

	#
	# WMAP
	# Find a target matching this id
	#
	def get_target(id)
		target = WmapTarget.find(:first, :conditions => [ "id = ?", id])
		return target
	end

	#
	# WMAP
	# Create a target
	#
	def create_target(host,port,ssl,sel)
		tar = WmapTarget.create(
				:host => host,
				:address => host,
				:port => port,
				:ssl => ssl,
				:selected => sel
			)
		#framework.events.on_db_target(rec)
	end


	#
	# WMAP
	# Create a request (by hand)
	#
	def create_request(host,port,ssl,meth,path,headers,query,body,respcode,resphead,response)
		req = WmapRequest.create(
				:host => host,
				:address => host,
				:port => port,
				:ssl => ssl,
				:meth => meth,
				:path => path,
				:headers => headers,
				:query => query,
				:body => body,
				:respcode => respcode,
				:resphead => resphead,
				:response => response
			)
		#framework.events.on_db_request(rec)
	end

	#
	# WMAP
	# Quick way to query the database (used by wmap_sql)
	#
	def sql_query(sqlquery)
		ActiveRecord::Base.connection.select_all(sqlquery)
	end

end

end

