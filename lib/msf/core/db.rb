require 'rex/parser/nmap_xml'

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
	Open      = "open"
	Closed    = "closed"
	Filtered  = "filtered"
	Unknown   = "unknown"
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

class DBImportError < RuntimeError
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
		res = Host.find(:first)
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
	# Wait for all pending write to finish
	#
	def sync
		task = queue( Proc.new { } )
		task.wait
	end

	#
	# Find a host.  Performs no database writes.
	#
	def get_host(opts)
		if opts.kind_of? Host
			return opts
		elsif opts.kind_of? String
			raise RuntimeError, "This invokation of get_host is no longer supported: #{caller}"
		else
			address = opts[:addr] || opts[:address] || opts[:host] || return
			return address if address.kind_of? Host
		end
		wspace = opts.delete(:workspace) || workspace
		host   = wspace.hosts.find_by_address(address)
		return host
	end

	#
	# Exactly like report_host but waits for the database to create a host and returns it.
	#
	def find_or_create_host(opts)
		report_host(opts.merge({:wait => true}))
	end

	#
	# Report a host's attributes such as operating system and service pack
	#
	# The opts parameter MUST contain
	#	:host       -- the host's ip address
	#
	# The opts parameter can contain:
	#	:state      -- one of the Msf::HostState constants
	#	:os_name    -- one of the Msf::OperatingSystems constants
	#	:os_flavor  -- something like "XP" or "Gentoo"
	#	:os_sp      -- something like "SP2"
	#	:os_lang    -- something like "English", "French", or "en-US"
	#	:arch       -- one of the ARCH_* constants
	#	:mac        -- the host's MAC address
	#
	def report_host(opts)
		return if not active
		addr = opts.delete(:host) || return
		return addr if addr.kind_of? Host
		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace

		if opts[:host_mac]
			opts[:mac] = opts.delete(:host_mac)
		end

		if addr !~ /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
			raise ::ArgumentError, "Invalid IP address in report_host(): #{addr}"
		end

		ret = {}
		task = queue( Proc.new {
			if opts[:comm] and opts[:comm].length > 0
				host = wspace.hosts.find_or_initialize_by_address_and_comm(addr, opts[:comm])
			else
				host = wspace.hosts.find_or_initialize_by_address(addr)
			end

			opts.each { |k,v|
				if (host.attribute_names.include?(k.to_s))
					host[k] = v
				else
					dlog("Unknown attribute for Host: #{k}")
				end
			}
			host.state     = HostState::Alive if not host.state
			host.comm      = ''        if not host.comm
			host.workspace = wspace    if not host.workspace

			if (host.changed?)
				host.save!
			end
			ret[:host] = host
		} )
		if wait
			return nil if task.wait != :done
			return ret[:host]
		end
		return task
	end

	#
	# Iterates over the hosts table calling the supplied block with the host
	# instance of each entry.
	#
	def each_host(wspace=workspace, &block)
		wspace.hosts.each do |host|
			block.call(host)
		end
	end

	#
	# Returns a list of all hosts in the database
	#
	def hosts(wspace = workspace, only_up = false, addresses = nil)
		conditions = {}
		conditions[:state] = [Msf::HostState::Alive, Msf::HostState::Unknown] if only_up
		conditions[:address] = addresses if addresses
		wspace.hosts.all(:conditions => conditions, :order => :address)
	end



	def find_or_create_service(opts)
		report_service(opts.merge({:wait => true}))
	end

	#
	# Record a service in the database.
	#
	# opts must contain
	#	:host  -- the host where this service is running
	#	:port  -- the port where this service listens
	#	:proto -- the protocol (e.g. tcp, udp...)
	#
	def report_service(opts)
		return if not active
		addr = opts.delete(:host) || return
		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace

		hopts = {:workspace => wspace, :host => addr}

		if opts[:host_name]
			hopts[:name] = opts.delete(:host_name)
		end

		if opts[:host_mac]
			hopts[:mac] = opts.delete(:host_mac)
		end
		report_host(hopts)

		ret  = {}

		task = queue(Proc.new {
			host = get_host(:workspace => wspace, :address => addr)
			host.state = HostState::Alive
			host.save! if host.changed?

			proto = opts[:proto] || 'tcp'
			opts[:name].downcase! if (opts[:name])

			service = host.services.find_or_initialize_by_port_and_proto(opts[:port].to_i, proto)
			opts.each { |k,v|
				if (service.attribute_names.include?(k.to_s))
					service[k] = v
				else
					dlog("Unknown attribute for Service: #{k}")
				end
			}
			if (service.state == nil)
				service.state = ServiceState::Open
			end
			if (service and service.changed?)
				service.save!
			end
			ret[:service] = service
		})
		if wait
			return nil if task.wait() != :done
			return ret[:service]
		end
		return task
	end

	def get_service(wspace, host, proto, port)
		host = get_host(:workspace => wspace, :address => host)
		return if not host
		return host.services.find_by_proto_and_port(proto, port)
	end

	#
	# Iterates over the services table calling the supplied block with the
	# service instance of each entry.
	#
	def each_service(wspace=workspace, &block)
		services(wspace).each do |service|
			block.call(service)
		end
	end

	#
	# Returns a list of all services in the database
	#
	def services(wspace = workspace, only_up = false, proto = nil, addresses = nil, ports = nil, names = nil)
		conditions = {}
		conditions[:state] = [ServiceState::Open] if only_up
		conditions[:proto] = proto if proto
		conditions["hosts.address"] = addresses if addresses
		conditions[:port] = ports if ports
		conditions[:name] = names if names
		wspace.services.all(:include => :host, :conditions => conditions, :order => "hosts.address, port")
	end


	def get_client(opts)
		wspace = opts.delete(:workspace) || workspace
		host   = get_host(:workspace => wspace, :host => opts[:host]) || return
		client = host.clients.find(:first, :conditions => {:ua_string => opts[:ua_string]})
		return client
	end

	def find_or_create_client(opts)
		report_client(opts.merge({:wait => true}))
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
	# Returns a Client.
	#
	def report_client(opts)
		return if not active
		addr = opts.delete(:host) || return
		wspace = opts.delete(:workspace) || workspace
		report_host(:workspace => wspace, :host => addr)
		wait = opts.delete(:wait)

		ret = {}
		task = queue(Proc.new {
			host = get_host(:workspace => wspace, :host => addr)
			client = host.clients.find_or_initialize_by_ua_string(opts[:ua_string])
			opts.each { |k,v|
				if (client.attribute_names.include?(k.to_s))
					client[k] = v
				else
					dlog("Unknown attribute for Client: #{k}")
				end
			}
			if (client and client.changed?)
				client.save!
			end
			ret[:client] = client
		})
		if wait
			return nil if task.wait() != :done
			return ret[:client]
		end
		return task
	end

	#
	# This method iterates the vulns table calling the supplied block with the
	# vuln instance of each entry.
	#
	def each_vuln(wspace=workspace,&block)
		wspace.vulns.each do |vulns|
			block.call(vulns)
		end
	end

	#
	# This methods returns a list of all vulnerabilities in the database
	#
	def vulns(wspace=workspace)
		wspace.vulns
	end

	#
	# This method iterates the notes table calling the supplied block with the
	# note instance of each entry.
	#
	def each_note(wspace=workspace, &block)
		wspace.notes.each do |note|
			block.call(note)
		end
	end

	#
	# Find or create a note matching this type/data
	#
	def find_or_create_note(opts)
		report_note(opts.merge({:wait => true}))
	end

	def report_note(opts)
		return if not active
		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace
		seen = opts.delete(:seen) || false
		crit = opts.delete(:critical) || false
		host = nil
		addr = nil
		# Report the host so it's there for the Proc to use below
		if opts[:host]
			if opts[:host].kind_of? Host
				host = opts[:host]
			else
				report_host({:workspace => wspace, :host => opts[:host]})
				addr = opts[:host]
			end
		end

		# Update Modes can be :unique, :unique_data, :insert
		mode = opts[:update] || :unique

		ret = {}
		task = queue(Proc.new {
			if addr and not host
				host = get_host(:workspace => wspace, :host => addr)
			end
			host.state = HostState::Alive
			host.save! if host.changed?

			ntype  = opts.delete(:type) || opts.delete(:ntype) || return
			data   = opts[:data] || return
			method = nil
			args   = []
			note   = nil

			case mode
			when :unique
				method = "find_or_initialize_by_ntype"
				args = [ ntype ]
			when :unique_data
				method = "find_or_initialize_by_ntype_and_data"
				args = [ ntype, data.to_yaml ]
			end

			# Find and update a record by type
			if(method)
				if host
					method << "_and_host_id"
					args.push(host[:id])
				end
				if opts[:service] and opts[:service].kind_of? Service
					method << "_and_service_id"
					args.push(opts[:service][:id])
				end

				note = wspace.notes.send(method, *args)
				if (note.changed?)
					note.data    = data
					note.save!
				end
			# Insert a brand new note record no matter what
			else
				note = wspace.notes.new
				if host
					note.host_id = host[:id]
				end
				if opts[:service] and opts[:service].kind_of? Service
					note.service_id = opts[:service][:id]
				end
				note.seen     = seen
				note.critical = crit
				note.ntype    = ntype
				note.data     = data
				note.save!
			end

			ret[:note] = note
		})
		if wait
			return nil if task.wait() != :done
			return ret[:note]
		end
		return task
	end

	#
	# This methods returns a list of all notes in the database
	#
	def notes(wspace=workspace)
		wspace.notes
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
		return if not active
		host    = opts.delete(:host)
		service = opts.delete(:service)
		wspace  = opts.delete(:workspace) || workspace
		proto   = opts.delete(:proto) || "generic"
		proto   = proto.downcase

		note = {
			:workspace => wspace,
			:type      => "auth.#{proto}",
			:host      => host,
			:service   => service,
			:data      => opts,
			:update    => :unique_data
		}

		return report_note(note)
	end

	def get_auth_info(opts={})
		return if not active
		wspace = opts.delete(:workspace) || workspace
		condition = ""
		condition_values = []
		if opts[:host]
			host = get_host(:workspace => wspace, :address => opts[:host])
			condition = "host_id == ?"
			condition_values = host[:id]
		end
		if opts[:proto]
			if condition.length > 0
				condition << " and "
			end
			condition << "ntype = ?"
			condition_values << "auth.#{opts[:proto].downcase}"
		else
			if condition.length > 0
				condition << " and "
			end
			condition << "ntype LIKE ?"
			condition_values << "auth.%"
		end

		if condition.length > 0
			condition << " and "
		end
		condition << "workspace_id == ?"
		condition_values << wspace[:id]

		conditions = [ condition ] + condition_values
		info = notes.find(:all, :conditions => conditions )
		return info.map{|i| i.data} if info
	end




	#
	# Find or create a vuln matching this service/name
	#
	def find_or_create_vuln(opts)
		report_vuln(opts.merge({:wait => true}))
	end

	#
	#
	#
	def report_vuln(opts)
		return if not active
		name = opts[:name] || return
		data = opts[:data]
		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace
		rids = nil
		if opts[:refs]
			rids = []
			opts[:refs].each do |r|
				if r.respond_to? :ctx_id
					r = r.ctx_id + '-' + r.ctx_val
				end
				rids << find_or_create_ref(:name => r)
			end
		end
		host = nil
		addr = nil
		if opts[:host]
			if opts[:host].kind_of? Host
				host = opts[:host]
			else
				report_host({:workspace => wspace, :host => opts[:host]})
				addr = opts[:host]
			end
		end

		ret = {}
		task = queue( Proc.new {
			host = get_host(:workspace => wspace, :address => addr)
			host.state = HostState::Alive
			host.save! if host.changed?

			if data
				vuln = host.vulns.find_or_initialize_by_name_and_data(name, data, :include => :refs)
			else
				vuln = host.vulns.find_or_initialize_by_name(name, :include => :refs)
			end

			if opts[:port] and opts[:proto]
				vuln.service = host.services.find_or_create_by_port_and_proto(opts[:port], opts[:proto])
			elsif opts[:port]
				vuln.service = host.services.find_or_create_by_port(opts[:port])
			end

			if rids
				vuln.refs << (rids - vuln.refs)
			end

			if vuln.changed?
				vuln.save!
			end
			ret[:vuln] = vuln
		})
		if wait
			return nil if task.wait() != :done
			return ret[:vuln]
		end
		return task
	end

	def get_vuln(wspace, host, service, name, data='')
		raise RuntimeError, "Not workspace safe: #{caller.inspect}"
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
		ret = {}
		task = queue(Proc.new {
			ref = Ref.find_or_initialize_by_name(opts[:name])
			if ref and ref.changed?
				ref.save!
			end
			ret[:ref] = ref
		})
		return nil if task.wait() != :done
		return ret[:ref]
	end
	def get_ref(name)
		Ref.find_by_name(name)
	end


	#
	# Deletes a host and associated data matching this address/comm
	#
	def del_host(wspace, address, comm='')
		host = wspace.hosts.find_by_address_and_comm(address, comm)
		host.destroy if host
	end

	#
	# Deletes a port and associated vulns matching this port
	#
	def del_service(wspace, address, proto, port, comm='')

		host = get_host(:workspace => wspace, :address => address)
		return unless host

		host.services.all(:conditions => {:proto => proto, :port => port}).each { |s| s.destroy }
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
	def has_host?(wspace,addr)
		wspace.hosts.find_by_address(addr)
	end

	def events(wspace=workspace)
		wspace.events.find :all, :order => 'created_at ASC'
	end

	def report_event(opts = {})
		return if not active
		wspace = opts.delete(:workspace) || workspace
		uname  = opts.delete(:username)

		if opts[:host]
			report_host(:workspace => wspace, :host => opts[:host])
		end
		framework.db.queue(Proc.new {
			opts[:host] = get_host(:workspace => wspace, :host => opts[:host]) if opts[:host]
			Event.create(opts.merge(:workspace_id => wspace[:id], :username => uname))
		})
	end

	#
	# Loot collection
	#
	#
	# This method iterates the loot table calling the supplied block with the
	# instance of each entry.
	#
	def each_loot(wspace=workspace, &block)
		wspace.loots.each do |note|
			block.call(note)
		end
	end

	#
	# Find or create a loot matching this type/data
	#
	def find_or_create_loot(opts)
		report_loot(opts.merge({:wait => true}))
	end

	def report_loot(opts)
		return if not active
		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace
		path = opts.delete(:path)

		host = nil
		addr = nil

		# Report the host so it's there for the Proc to use below
		if opts[:host]
			if opts[:host].kind_of? Host
				host = opts[:host]
			else
				report_host({:workspace => wspace, :host => opts[:host]})
				addr = opts[:host]
			end
		end

		ret = {}
		task = queue(Proc.new {

			if addr and not host
				host = get_host(:workspace => wspace, :host => addr)
			end

			ltype  = opts.delete(:type) || opts.delete(:ltype) || return
			ctype  = opts.delete(:ctype) || opts.delete(:content_type) || 'text/plain'
			name   = opts.delete(:name)
			info   = opts.delete(:info)
			data   = opts[:data]
			loot   = wspace.loots.new

			if host
				loot.host_id = host[:id]
			end
			if opts[:service] and opts[:service].kind_of? Service
				loot.service_id = opts[:service][:id]
			end

			loot.path  = path
			loot.ltype = ltype
			loot.content_type = ctype
			loot.data  = data
			loot.name  = name if name
			loot.info  = info if info
			loot.save!

			ret[:loot] = loot
		})

		if wait
			return nil if task.wait() != :done
			return ret[:loot]
		end
		return task
	end

	#
	# This methods returns a list of all notes in the database
	#
	def loots(wspace=workspace)
		wspace.loots
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


	##
	#
	# Import methods
	#
	##

	#
	# Generic importer that automatically determines the file type being
	# imported.  Since this looks for vendor-specific strings in the given
	# file, there shouldn't be any false detections, but no guarantees.
	#
	def import_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)
		import(data, wspace)
	end

	def import(data, wspace=workspace)
		di = data.index("\n")
		if(not di)
			raise DBImportError.new("Could not automatically determine file type")
		end
		firstline = data[0, di]
		if (firstline.index("<NeXposeSimpleXML"))
			return import_nexpose_simplexml(data, wspace)
		elsif (firstline.index("<?xml"))
			# it's xml, check for root tags we can handle
			line_count = 0
			data.each_line { |line|
				line =~ /<([a-zA-Z0-9\-\_]+)[ >]/
				case $1
				when "nmaprun"
					return import_nmap_xml(data, wspace)
				when "openvas-report"
					return import_openvas_xml(data, wspace)
				when "NessusClientData"
					return import_nessus_xml(data, wspace)
				when "NessusClientData_v2"
					return import_nessus_xml_v2(data, wspace)
				else
					# Give up if we haven't hit the root tag in the first few lines
					break if line_count > 10
				end
				line_count += 1
			}
		elsif (firstline.index("timestamps|||scan_start"))
			# then it's a nessus nbe
			return import_nessus_nbe(data, wspace)
		elsif (firstline.index("# amap v"))
			# then it's an amap mlog
			return import_amap_mlog(data, wspace)
		end
		raise DBImportError.new("Could not automatically determine file type")
	end

	#
	# Nexpose Simple XML
	#
	# XXX At some point we'll want to make this a stream parser for dealing
	# with large results files
	#
	def import_nexpose_simplexml_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)
		import_nexpose_simplexml(data, wspace)
	end

	def import_nexpose_simplexml(data, wspace=workspace)
		if data.kind_of? REXML::Document
			doc = data
		else
			doc = REXML::Document.new(data)
		end
		doc.elements.each('/NeXposeSimpleXML/devices/device') do |dev|
			addr = dev.attributes['address'].to_s

			fprint = {}

			dev.elements.each('fingerprint/description') do |str|
				fprint[:desc] = str.text.to_s.strip
			end
			dev.elements.each('fingerprint/vendor') do |str|
				fprint[:vendor] = str.text.to_s.strip
			end
			dev.elements.each('fingerprint/family') do |str|
				fprint[:family] = str.text.to_s.strip
			end
			dev.elements.each('fingerprint/product') do |str|
				fprint[:product] = str.text.to_s.strip
			end
			dev.elements.each('fingerprint/version') do |str|
				fprint[:version] = str.text.to_s.strip
			end
			dev.elements.each('fingerprint/architecture') do |str|
				fprint[:arch] = str.text.to_s.upcase.strip
			end

			conf = {
				:workspace => wspace,
				:host      => addr,
				:state     => Msf::HostState::Alive,
				:os_flavor => fprint[:desc].to_s

			}

			conf[:arch] = fprint[:arch] if fprint[:arch]
			report_host(conf)

			report_note(
				:workspace => wspace,
				:host      => addr,
				:type      => 'host.os.nexpose_fingerprint',
				:data      => fprint
			)

			# Load vulnerabilities not associated with a service
			dev.elements.each('vulnerabilities/vulnerability') do |vuln|
				vid  = vuln.attributes['id'].to_s.downcase
				refs = process_nexpose_data_sxml_refs(vuln)
				next if not refs
				report_vuln(
					:workspace => wspace,
					:host      => addr,
					:name      => 'NEXPOSE-' + vid,
					:data      => vid,
					:refs      => refs)
			end

			# Load the services
			dev.elements.each('services/service') do |svc|
				sname = svc.attributes['name'].to_s
				sprot = svc.attributes['protocol'].to_s.downcase
				sport = svc.attributes['port'].to_s.to_i

				name = sname.split('(')[0].strip
				info = ''

				svc.elements.each('fingerprint/description') do |str|
					info = str.text.to_s.strip
				end

				if(sname.downcase != '<unknown>')
					report_service(:workspace => wspace, :host => addr, :proto => sprot, :port => sport, :name => name, :info => info)
				else
					report_service(:workspace => wspace, :host => addr, :proto => sprot, :port => sport, :info => info)
				end

				# Load vulnerabilities associated with this service
				svc.elements.each('vulnerabilities/vulnerability') do |vuln|
					vid  = vuln.attributes['id'].to_s.downcase
					refs = process_nexpose_data_sxml_refs(vuln)
					next if not refs
					report_vuln(
						:workspace => wspace,
						:host => addr,
						:port => sport,
						:proto => sprot,
						:name => 'NEXPOSE-' + vid,
						:data => vid,
						:refs => refs)
				end
			end
		end
	end


	#
	# Nexpose Raw XML
	#
	# XXX At some point we'll want to make this a stream parser for dealing
	# with large results files
	#
	def import_nexpose_rawxml_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)
		import_nexpose_rawxml(data, wspace)
	end
	def import_nexpose_rawxml(data, wspace=workspace)
		doc = REXML::Document.new(data)
		doc.elements.each('/NexposeReport/nodes/node') do |host|
			addr = host.attributes['address']
			xhost = addr
			refs = {}

			# os based vuln
			host.elements['tests'].elements.each('test') do |vuln|
				if vuln.attributes['status'] == 'vulnerable-exploited' or vuln.attributes['status'] == 'vulnerable-version'
					dhost = find_or_create_host(:workspace => wspace, :host => addr)
					next if not dhost

					vid = vuln.attributes['id'].to_s
					nexpose_vuln_lookup(wspace,doc,vid,refs,dhost)
					nexpose_vuln_lookup(wspace,doc,vid.upcase,refs,dhost)
				end
			end

			# skip if no endpoints
			next unless host.elements['endpoints']

			# parse the ports and add the vulns
			host.elements['endpoints'].elements.each('endpoint') do |port|
				prot = port.attributes['protocol']
				pnum = port.attributes['port']
				stat = port.attributes['status']
				next if not port.elements['services']
				name = port.elements['services'].elements['service'].attributes['name'].downcase

				next if not port.elements['services'].elements['service'].elements['fingerprints']
				prod = port.elements['services'].elements['service'].elements['fingerprints'].elements['fingerprint'].attributes['product']
				vers = port.elements['services'].elements['service'].elements['fingerprints'].elements['fingerprint'].attributes['version']
				vndr = port.elements['services'].elements['service'].elements['fingerprints'].elements['fingerprint'].attributes['vendor']

				next if stat != 'open'

				dhost = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)
				next if not dhost

				if name != "unknown"
					service = find_or_create_service(:workspace => wspace, :host => dhost, :proto => prot.downcase, :port => pnum.to_i, :name => name)
				else
					service = find_or_create_service(:workspace => wspace, :host => dhost, :proto => prot.downcase, :port => pnum.to_i)
				end

				port.elements['services'].elements['service'].elements['tests'].elements.each('test') do |vuln|
					if vuln.attributes['status'] == 'vulnerable-exploited' or vuln.attributes['status'] == 'vulnerable-version'
						vid = vuln.attributes['id'].to_s
						# TODO, improve the vuln_lookup check so case of the vuln_id doesnt matter
						nexpose_vuln_lookup(doc,vid,refs,dhost,service)
						nexpose_vuln_lookup(doc,vid.upcase,refs,dhost,service)
					end
				end
			end
		end
	end

	#
	# Import Nmap's -oX xml output
	#
	def import_nmap_xml_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)
		import_nmap_xml(data, wspace)
	end

	def import_nmap_xml(data, wspace=workspace)
		# Use a stream parser instead of a tree parser so we can deal with
		# huge results files without running out of memory.
		parser = Rex::Parser::NmapXMLStreamParser.new

		# Whenever the parser pulls a host out of the nmap results, store
		# it, along with any associated services, in the database.
		parser.on_found_host = Proc.new { |h|

			data = {:workspace => wspace}
			if (h["addrs"].has_key?("ipv4"))
				addr = h["addrs"]["ipv4"]
			elsif (h["addrs"].has_key?("ipv6"))
				addr = h["addrs"]["ipv6"]
			else
				# Can't report it if it doesn't have an IP
				return
			end
			data[:host] = addr
			if (h["addrs"].has_key?("mac"))
				data[:mac] = h["addrs"]["mac"]
			end
			data[:state] = (h["status"] == "up") ? Msf::HostState::Alive : Msf::HostState::Dead

			# XXX: There can be multiple matches, but we only see the *last* right now
			if (h["os_accuracy"] and h["os_accuracy"].to_i > 95)
				data[:os_name] = h["os_vendor"]
				data[:os_sp]   = h["os_version"]
			end

			# Only passed through if its a 100% match
			if (h["os_match"])
				arch = nil
				case h["os_match"]
				when /x86|intel/i
					data[:arch] = ARCH_X86
				when /ppc|powerpc/i
					data[:arch] = ARCH_PPC
				when /sparc/i
					data[:arch] = ARCH_SPARC
				when /armle/i
					data[:arch] = ARCH_ARMLE
				when /armbe/i
					data[:arch] = ARCH_ARMBE
				end
				data[:os_flavor] = h["os_match"]
			end

			if ( h["reverse_dns"] )
				data[:name] = h["reverse_dns"]
			end

			if(data[:state] != Msf::HostState::Dead)
				report_host(data)
			end

			if( data[:os_name] )
				note = {
					:workspace => wspace,
					:host => addr,
					:type => 'host.os.nmap_fingerprint',
					:data => {
						:os_vendor   => h["os_vendor"],
						:os_family   => h["os_family"],
						:os_version  => h["os_version"],
						:os_accuracy => h["os_accuracy"]
					}
				}

				if(h["os_match"])
					note[:data][:os_match] = h['os_match']
				end

				report_note(note)
			end

			if (h["last_boot"])
				report_note(
					:workspace => wspace,
					:host => addr,
					:type => 'host.last_boot',
					:data => {
						:time => h["last_boot"]
					}
				)
			end

			# Put all the ports, regardless of state, into the db.
			h["ports"].each { |p|
				extra = ""
				extra << p["product"]   + " " if p["product"]
				extra << p["version"]   + " " if p["version"]
				extra << p["extrainfo"] + " " if p["extrainfo"]

				data = {}
				data[:workspace] = wspace
				data[:proto] = p["protocol"].downcase
				data[:port]  = p["portid"].to_i
				data[:state] = p["state"]
				data[:host]  = addr
				data[:info]  = extra if not extra.empty?
				if p["name"] != "unknown"
					data[:name] = p["name"]
				end
				report_service(data)
			}
		}

		REXML::Document.parse_stream(data, parser)
	end

	#
	# Import Nessus NBE files
	#
	def import_nessus_nbe_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)
		import_nessus_nbe(data, wspace)
	end
	def import_nessus_nbe(data, wspace=workspace)
		data.each_line do |line|
			r = line.split('|')
			next if r[0] != 'results'
			addr = r[2]
			port = r[3]
			nasl = r[4]
			type = r[5]
			data = r[6]

			# Match the NBE types with the XML severity ratings
			case type
			# log messages don't actually have any data, they are just
			# complaints about not being able to perform this or that test
			# because such-and-such was missing
			when "Log Message"; next
			when "Security Hole"; severity = 3
			when "Security Warning"; severity = 2
			when "Security Note"; severity = 1
			# a severity 0 means there's no extra data, it's just an open port
			else; severity = 0
			end
			handle_nessus(wspace, addr, port, nasl, severity, data)
		end
	end

	#
	# Of course they had to change the nessus format.
	#
	def import_openvas_xml(filename)
		raise DBImportError.new("No OpenVAS XML support. Please submit a patch to msfdev[at]metasploit.com")
	end

	#
	# Import Nessus XML v1 and v2 output
	#
	# Old versions of openvas exported this as well
	#
	def import_nessus_xml_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)

		if data.index("NessusClientData_v2")
			import_nessus_xml_v2(data, wspace)
		else
			import_nessus_xml(data, wspace)
		end
	end

	def import_nessus_xml(data, wspace=workspace)

		doc = REXML::Document.new(data)
		doc.elements.each('/NessusClientData/Report/ReportHost') do |host|
			addr = host.elements['HostName'].text

			host.elements.each('ReportItem') do |item|
				nasl = item.elements['pluginID'].text
				port = item.elements['port'].text
				data = item.elements['data'].text
				severity = item.elements['severity'].text

				handle_nessus(wspace, addr, port, nasl, severity, data)
			end
		end
	end

	def import_nessus_xml_v2(data, wspace=workspace)
		doc = REXML::Document.new(data)
		doc.elements.each('/NessusClientData_v2/Report/ReportHost') do |host|
			# if Nessus resovled the host, its host-ip tag should be set
			# otherwise, fall back to the name attribute which would
			# logically need to be an IP address
			begin
				addr = host.elements["HostProperties/tag[@name='host-ip']"].text
			rescue
				addr = host.attribute("name").value
			end

			host.elements.each('ReportItem') do |item|
				nasl = item.attribute('pluginID').value
				port = item.attribute('port').value
				proto = item.attribute('protocol').value
				name = item.attribute('svc_name').value
				severity = item.attribute('severity').value
				description = item.elements['plugin_output']
				cve = item.elements['cve']
				bid = item.elements['bid']
				xref = item.elements['xref']

				handle_nessus_v2(wspace, addr, port, proto, name, nasl, severity, description, cve, bid, xref)

			end
		end
	end

	def import_ip_list_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)
		import_ip_list(data, wspace)
	end

	def import_ip_list(data, wspace)
		data.each_line do |line|
			host = find_or_create_host(:workspace => wspace, :host=> line, :state => Msf::HostState::Alive)
		end
	end

	def import_amap_log_file(filename, wspace=workspace)
		f = File.open(filename, 'r')
		data = f.read(f.stat.size)
		import_amap_log(data, wspace)
	end
	def import_amap_mlog(data, wspace)
		data.each_line do |line|
			next if line =~ /^#/
			r = line.split(':')
			next if r.length < 6

			addr   = r[0]
			port   = r[1].to_i
			proto  = r[2].downcase
			status = r[3]
			name   = r[5]
			next if status != "open"

			host = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)
			next if not host
			info = {
				:workspace => wspace,
				:host => host,
				:proto => proto,
				:port => port
			}
			if name != "unidentified"
				info[:name] = name
			end
			service = find_or_create_service(info)
		end
	end

protected

	#
	# This holds all of the shared parsing/handling used by the
	# Nessus NBE and NESSUS v1 methods
	#
	def handle_nessus(wspace, addr, port, nasl, severity, data)
		# The port section looks like:
		#   http (80/tcp)
		p = port.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
		return if not p

		report_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)
		name = p[1].strip
		port = p[2].to_i
		proto = p[3].downcase

		info = { :workspace => wspace, :host => addr, :port => port, :proto => proto }
		if name != "unknown" and name[-1,1] != "?"
			info[:name] = name
		end
		report_service(info)

		return if not nasl

		data.gsub!("\\n", "\n")

		refs = []

		if (data =~ /^CVE : (.*)$/)
			$1.gsub(/C(VE|AN)\-/, '').split(',').map { |r| r.strip }.each do |r|
				refs.push('CVE-' + r)
			end
		end

		if (data =~ /^BID : (.*)$/)
			$1.split(',').map { |r| r.strip }.each do |r|
				refs.push('BID-' + r)
			end
		end

		if (data =~ /^Other references : (.*)$/)
			$1.split(',').map { |r| r.strip }.each do |r|
				ref_id, ref_val = r.split(':')
				ref_val ? refs.push(ref_id + '-' + ref_val) : refs.push(ref_id)
			end
		end

		nss = 'NSS-' + nasl.to_s

		report_vuln(
			:workspace => wspace,
			:host => addr,
			:port => port,
			:proto => proto,
			:name => nss,
			:data => data,
			:refs => refs)
	end

	#
	# NESSUS v2 file format has a dramatically different layout
	# for ReportItem data
	#
	def handle_nessus_v2(wspace,addr,port,proto,name,nasl,severity,description,cve,bid,xref)

		report_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)

		info = { :workspace => wspace, :host => addr, :port => port, :proto => proto }
		if name != "unknown" and name[-1,1] != "?"
			info[:name] = name
		end

		report_service(info)

		return if nasl == "0"

		refs = []

		cve.collect do |r|
			r.to_s.gsub!(/C(VE|AN)\-/, '')
			refs.push('CVE-' + r.to_s)
		end if cve

		bid.collect do |r|
			refs.push('BID-' + r.to_s)
		end if bid

		xref.collect do |r|
			ref_id, ref_val = r.to_s.split(':')
			ref_val ? refs.push(ref_id + '-' + ref_val) : refs.push(ref_id)
		end if xref

		nss = 'NSS-' + nasl

		report_vuln(
			:workspace => wspace,
			:host => addr,
			:port => port,
			:proto => proto,
			:name => nss,
			:data => description ? description.text : "",
			:refs => refs)
	end

	def process_nexpose_data_sxml_refs(vuln)
		refs = []
		vid = vuln.attributes['id'].to_s.downcase
		vry = vuln.attributes['resultCode'].to_s.upcase

		# Only process vuln-exploitable and vuln-version statuses
		return if vry !~ /^V[VE]$/

		refs = []
		vuln.elements.each('id') do |ref|
			rtyp = ref.attributes['type'].to_s.upcase
			rval = ref.text.to_s.strip
			case rtyp
			when 'CVE'
				refs << rval.gsub('CAN', 'CVE')
			when 'MS' # obsolete?
				refs << "MSB-MS-#{rval}"
			else
				refs << "#{rtyp}-#{rval}"
			end
		end

		refs << "NEXPOSE-#{vid}"
		refs
	end

	#
	# NeXpose vuln lookup
	#
	def nexpose_vuln_lookup(wspace, doc, vid, refs, host, serv=nil)
		doc.elements.each("/NexposeReport/VulnerabilityDefinitions/vulnerability[@id = '#{vid}']]") do |vulndef|

			title = vulndef.attributes['title']
			pciSeverity = vulndef.attributes['pciSeverity']
			cvss_score = vulndef.attributes['cvssScore']
			cvss_vector = vulndef.attributes['cvssVector']

			vulndef.elements['references'].elements.each('reference') do |ref|
				if ref.attributes['source'] == 'BID'
					refs[ 'BID-' + ref.text ] = true
				elsif ref.attributes['source'] == 'CVE'
					# ref.text is CVE-$ID
					refs[ ref.text ] = true
				elsif ref.attributes['source'] == 'MS'
					refs[ 'MSB-MS-' + ref.text ] = true
				end
			end

			refs[ 'NEXPOSE-' + vid.downcase ] = true

			vuln = find_or_create_vuln(
				:workspace => wspace,
				:host => host,
				:service => serv,
				:name => 'NEXPOSE-' + vid.downcase,
				:data => title)

			rids = []
			refs.keys.each do |r|
				rids << find_or_create_ref(:name => r)
			end

			vuln.refs << (rids - vuln.refs)
		end
	end

end

end

