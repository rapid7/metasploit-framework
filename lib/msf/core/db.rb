require 'rex/parser/nmap_xml'
require 'rex/parser/nexpose_xml'
require 'rex/socket'
require 'zip'
require 'tmpdir'
require 'fileutils'

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

	def ipv4_validator(addr)
		return false unless addr.kind_of? String
		addr =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
	end

	# Takes a space-delimited set of ips and ranges, and subjects
	# them to RangeWalker for validation. Returns true or false.
	def validate_ips(ips)
		ret = true
		begin
			ips.split(' ').each {|ip|
				unless Rex::Socket::RangeWalker.new(ip).ranges
					ret = false
					break
				end
				}
		rescue
			ret = false
		end
		return ret
	end


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

		# Ensure the host field updated_at is changed on each report_host()
		if addr.kind_of? Host
			queue( Proc.new { addr.updated_at = addr.created_at; addr.save! } )
			return addr
		end

		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace

		if opts[:host_mac]
			opts[:mac] = opts.delete(:host_mac)
		end

		unless ipv4_validator(addr)
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
			host.info = host.info[0,Host.columns_hash["info"].limit] if host.info

			# Set default fields if needed
			host.state       = HostState::Alive if not host.state
			host.comm        = ''        if not host.comm
			host.workspace   = wspace    if not host.workspace

			# Always save the host, helps track updates
			msfe_import_timestamps(opts,host)
			host.save!

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
		addr  = opts.delete(:host) || return
		hname = opts.delete(:host_name)
		hmac  = opts.delete(:host_mac)

		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace

		hopts = {:workspace => wspace, :host => addr}
		hopts[:name] = hname if hname
		hopts[:mac]  = hmac  if hmac
		report_host(hopts)

		ret  = {}

		task = queue(Proc.new {
			host = get_host(:workspace => wspace, :address => addr)
			if host
				host.updated_at = host.created_at
				host.state      = HostState::Alive
				host.save!
			end

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
				msfe_import_timestamps(opts,service)
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
	# This methods returns a list of all credentials in the database
	#
	def creds(wspace=workspace)
		Cred.find(
			:all,
			:include => {:service => :host}, # That's some magic right there.
			:conditions => ["hosts.workspace_id = ?", wspace.id]
		)
	end

	#
	# This method returns a list of all exploited hosts in the database.
	#
	def exploited_hosts(wspace=workspace)
		wspace.exploited_hosts
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

	#
	# Report a Note to the database.  Notes can be tied to a Workspace, Host, or Service.
	#
	# opts MUST contain
	#  :data  -- whatever it is you're making a note of
	#  :type  -- The type of note, e.g. smb_peer_os
	#
	# opts can contain
	#  :workspace  -- the workspace to associate with this Note
	#  :host       -- an IP address or a Host object to associate with this Note
	#  :service    -- a Service object to associate with this Note
	#  :port       -- along with :host and proto, a service to associate with this Note
	#  :proto      -- along with :host and port, a service to associate with this Note
	#  :update     -- what to do in case a similar Note exists, see below
	#
	# The :update option can have the following values:
	#  :unique       -- allow only a single Note per +host+/+type+ pair
	#  :unique_data  -- like :uniqe, but also compare +data+
	#  :insert       -- always insert a new Note even if one with identical values exists
	#
	# If the provided :host is an IP address and does not exist in the
	# database, it will be created.  If :workspace, :host and :service are all
	# omitted, the new Note will be associated with the current workspace.
	#
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
		# Do the same for a service
		if (opts[:proto] and opts[:port])
			report_service(
				:workspace => wspace,
				:host  => opts[:host],
				:proto => opts[:proto],
				:port  => opts[:port],
				:name  => opts[:sname]
			)
		end
		# Update Modes can be :unique, :unique_data, :insert
		mode = opts[:update] || :unique

		ret = {}
		task = queue(Proc.new {
			if addr and not host
				host = get_host(:workspace => wspace, :host => addr)
			end
			if not opts[:service] and (opts[:port] and opts[:proto])
				opts[:service] = get_service(wspace, host, opts[:proto], opts[:port])
			end

			if host
				host.updated_at = host.created_at
				host.state      = HostState::Alive
				host.save!
			end

			ntype  = opts.delete(:type) || opts.delete(:ntype) || (raise RuntimeError, "A note :type or :ntype is required")
			data   = opts[:data] || (raise RuntimeError, "Note :data is required")
			method = nil
			args   = []
			note   = nil

			case mode
			when :unique
				method = "find_or_initialize_by_ntype"
				args = [ ntype ]
			when :unique_data
				method = "find_or_initialize_by_ntype_and_data"
				args = [ ntype, data ]
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
					msfe_import_timestamps(opts,note)
					note.save!
				else
					note.updated_at = note.created_at
					msfe_import_timestamps(opts,note)
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
				msfe_import_timestamps(opts,note)
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

	# report_auth_info used to create a note, now it creates
	# an entry in the creds table. It's much more akin to
	# report_vuln() now.
	#
	# opts must contain
	#	:host    -- an IP address 
	#	:port    -- a port number 
	#
	# opts can contain
	#	:user  -- the username
	#	:pass  -- the password, or path to ssh_key
	#	:ptype  -- the type of password (password, hash, or ssh_key)
	#   :proto -- a transport name for the port
	#   :sname -- service name
	#	:active -- by default, a cred is active, unless explicitly false
	#	:proof  -- data used to prove the account is actually active.
	#
	# Sources: Credentials can be sourced from another credential, or from
	# a vulnerability. For example, if an exploit was used to dump the
	# smb_hashes, and this credential comes from there, the source_id would
	# be the Vuln id (as reported by report_vuln) and the type would be "Vuln".
	#
	#	:source_id   -- The Vuln or Cred id of the source of this cred.
	#	:source_type -- Either Vuln or Cred
	#
	# TODO: This is written somewhat host-centric, when really the 
	# Service is the thing. Need to revisit someday.
	def report_auth_info(opts={})
		return if not active
		raise ArgumentError.new("Missing required option :host") if opts[:host].nil? 
		raise ArgumentError.new("Invalid address for :host") unless validate_ips(opts[:host])
		raise ArgumentError.new("Missing required option :port") if opts[:port].nil?
		host = opts.delete(:host)
		ptype = opts.delete(:type) || "password"
		token = [opts.delete(:user), opts.delete(:pass)]
		sname = opts.delete(:sname)
		port = opts.delete(:port)
		proto = opts.delete(:proto) || "tcp"
		proof = opts.delete(:proof)
		source_id = opts.delete(:source_id)
		source_type = opts.delete(:source_type)
		# Nil is true for active.
		active = (opts[:active] || opts[:active].nil?) ? true : false

		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace

		# Service management; assume the user knows what
		# he's talking about.
		unless service = get_service(wspace, host, proto, port)
			report_service(:host => host, :port => port, :proto => proto, :name => sname, :workspace => wspace)
		end

		ret = {}
		task = queue( Proc.new {

			# Get the service
			service ||= get_service(wspace, host, proto, port)

			# Create the cred by username only (so we can change passwords) 
			cred = service.creds.find_or_initialize_by_user_and_ptype(token[0] || "", ptype)

			# Update with the password
			cred.pass = (token[1] || "")

			# Annotate the credential
			cred.ptype = ptype
			cred.active = active

			# Update the source ID only if there wasn't already one.
			if source_id and !cred.source_id
				cred.source_id = source_id 
				cred.source_type = source_type if source_type
			end

			# Safe proof (lazy way) -- doesn't chop expanded
			# characters correctly, but shouldn't ever be a problem.
			unless proof.nil?
				proof = Rex::Text.to_hex_ascii(proof) 
				proof = proof[0,4096]
			end
			cred.proof = proof

			# Update the timestamp
			if cred.changed?
				msfe_import_timestamps(opts,cred)
				cred.save!
			end

			# Ensure the updated_at is touched any time report_auth_info is called
			# except when it's set explicitly (as it is for imports)
			unless opts[:updated_at] || opts["updated_at"]
				cred.updated_at = Time.now.utc
				cred.save!
			end

			ret[:cred] = cred
		})
		if wait
			return nil if task.wait() != :done
			return ret[:cred]
		end
		return task
	end

	alias :report_cred :report_auth_info

	#
	# Find or create a credential matching this type/data
	#
	def find_or_create_cred(opts)
		report_auth_info(opts.merge({:wait => true}))
	end

	#
	# This method iterates the creds table calling the supplied block with the
	# cred instance of each entry.
	#
	def each_cred(wspace=workspace,&block)
		wspace.creds.each do |cred|
			block.call(cred)
		end
	end

	def each_exploited_host(wspace=workspace,&block)
		wspace.exploited_hosts.each do |eh|
			block.call(eh)
		end
	end

	#
	# Find or create a vuln matching this service/name
	#
	def find_or_create_vuln(opts)
		report_vuln(opts.merge({:wait => true}))
	end

	#
	# opts must contain
	#	:host  -- the host where this vulnerability resides
	#	:name  -- the scanner-specific id of the vuln (e.g. NEXPOSE-cifs-acct-password-never-expires)
	#
	# opts can contain
	#	:info  -- a human readable description of the vuln, free-form text
	#	:refs  -- an array of Ref objects or string names of references
	#
	def report_vuln(opts)
		return if not active
		raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
		raise ArgumentError.new("Deprecated data column for vuln, use .info instead") if opts[:data]
		name = opts[:name] || return
		info = opts[:info]
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
		if opts[:host].kind_of? Host
			host = opts[:host]
		else
			report_host({:workspace => wspace, :host => opts[:host]})
			addr = opts[:host]
		end

		ret = {}
		task = queue( Proc.new {
			if host
				host.updated_at = host.created_at
				host.state      = HostState::Alive
				host.save!
			else
				host = get_host(:workspace => wspace, :address => addr)
			end

			if info
				vuln = host.vulns.find_or_initialize_by_name_and_info(name, info, :include => :refs)
			else
				vuln = host.vulns.find_or_initialize_by_name(name, :include => :refs)
			end

			if opts[:port] and opts[:proto]
				vuln.service = host.services.find_or_create_by_port_and_proto(opts[:port], opts[:proto])
			elsif opts[:port]
				vuln.service = host.services.find_or_create_by_port_and_proto(opts[:port], "tcp")
			end

			if rids
				vuln.refs << (rids - vuln.refs)
			end

			if vuln.changed?
				msfe_import_timestamps(opts,vuln)
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
		ret[:ref] = get_ref(opts[:name])
		return ret[:ref] if ret[:ref]

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

	def report_exploit(opts={})
		return if not active
		raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
		wait   = opts[:wait]
		wspace = opts.delete(:workspace) || workspace
		host = nil
		addr = nil
		sname = opts.delete(:sname)
		port = opts.delete(:port)
		proto = opts.delete(:proto) || "tcp"
		name = opts.delete(:name)
		payload = opts.delete(:payload)
		session_uuid = opts.delete(:session_uuid) 

		if opts[:host].kind_of? Host
			host = opts[:host]
		else
			report_host({:workspace => wspace, :host => opts[:host]})
			addr = opts[:host]
		end

		if opts[:service].kind_of? Service
			service = opts[:service]
		elsif port
			report_service(:host => host, :port => port, :proto => proto, :name => sname)
			service = get_service(wspace, host, proto, port)
		else
			service = nil
		end

		ret = {}

		task = queue(
			Proc.new {
				if host
					host.updated_at = host.created_at
					host.state      = HostState::Alive
					host.save!
				else
					host = get_host(:workspace => wspace, :address => addr)
				end
				exploit_info = {
					:workspace => wspace,
					:host_id => host.id,
					:name => name,
					:payload => payload,
				}
				exploit_info[:service_id] = service.id if service
				exploit_info[:session_uuid] = session_uuid if session_uuid 
				exploit_record = ExploitedHost.create(exploit_info)
				exploit_record.save!

				ret[:exploit] = exploit_record
			}
		)

		if wait
			return nil if task.wait() != :done
			return ret[:exploit]
		end
		return task
		
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
		path = opts.delete(:path) || (raise RuntimeError, "A loot :path is required")

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

			ltype  = opts.delete(:type) || opts.delete(:ltype) || (raise RuntimeError, "A loot :type or :ltype is required")
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
			msfe_import_timestamps(opts,loot)
			loot.save!

			if !opts[:created_at]
				if host
					host.updated_at = host.created_at
					host.state      = HostState::Alive
					host.save!
				end
			end

			ret[:loot] = loot
		})

		if wait
			return nil if task.wait() != :done
			return ret[:loot]
		end
		return task
	end

	#
	# This methods returns a list of all loot in the database
	#
	def loots(wspace=workspace)
		wspace.loots
	end

	#
	# Find or create a task matching this type/data
	#
	def find_or_create_task(opts)
		report_task(opts.merge({:wait => true}))
	end

	def report_task(opts)
		return if not active
		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace
		path = opts.delete(:path) || (raise RuntimeError, "A task :path is required")

		ret = {}
		this_task = queue(Proc.new {

			user      = opts.delete(:user)
			desc      = opts.delete(:desc)
			error     = opts.delete(:error)
			info      = opts.delete(:info)
			mod       = opts.delete(:mod)
			options   = opts.delete(:options)
			prog      = opts.delete(:prog)
			result    = opts.delete(:result)
			completed_at = opts.delete(:completed_at)
			task      = wspace.tasks.new

			task.created_by = user
			task.description = desc
			task.error = error if error
			task.info = info
			task.module = mod
			task.options = options
			task.path = path
			task.progress = prog
			task.result = result if result
			msfe_import_timestamps(opts,task)
			# Having blank completed_ats, while accurate, will cause unstoppable tasks.
			if completed_at.nil? || completed_at.empty?
				task.completed_at = opts[:updated_at]
			else
				task.completed_at = completed_at
			end
			task.save!

			ret[:task] = task
		})

		if wait
			return nil if this_task.wait() != :done
			return ret[:task]
		end
		return this_task
	end

	#
	# This methods returns a list of all tasks in the database
	#
	def tasks(wspace=workspace)
		wspace.tasks
	end


	#
	# Find or create a task matching this type/data
	#
	def find_or_create_report(opts)
		report_report(opts.merge({:wait => true}))
	end

	def report_report(opts)
		return if not active
		wait = opts.delete(:wait)
		wspace = opts.delete(:workspace) || workspace
		path = opts.delete(:path) || (raise RuntimeError, "A report :path is required")

		ret = {}
		this_task = queue(Proc.new {

			user      = opts.delete(:user)
			options   = opts.delete(:options)
			rtype     = opts.delete(:rtype)
			report    = wspace.reports.new

			report.created_by = user
			report.options = options
			report.rtype = rtype
			report.path = path
			msfe_import_timestamps(opts,report)
			report.save!

			ret[:task] = report
		})

		if wait
			return nil if this_task.wait() != :done
			return ret[:task]
		end
		return this_task
	end

	#
	# This methods returns a list of all tasks in the database
	#
	def reports(wspace=workspace)
		wspace.reports
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


	# Returns a REXML::Document from the given data.
	def rexmlify(data)
		doc = data.kind_of?(REXML::Document) ? data : REXML::Document.new(data)
	end

	# Handles timestamps from Metasploit Express imports.
	def msfe_import_timestamps(opts,obj)
		obj.created_at = opts["created_at"] if opts["created_at"]
		obj.created_at = opts[:created_at] if opts[:created_at]
		obj.updated_at = opts["updated_at"] ? opts["updated_at"] : obj.created_at
		obj.updated_at = opts[:updated_at] ? opts[:updated_at] : obj.created_at
		return obj
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
	def import_file(args={}, &block)
		filename = args[:filename] || args['filename']
		wspace = args[:wspace] || args['wspace'] || workspace
		@import_filedata            = {}
		@import_filedata[:filename] = filename

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		if data[0,4] == "PK\x03\x04"
			data = Zip::ZipFile.open(filename)
		end
		if block
			import(args.merge(:data => data)) { |type,data| yield type,data }
		else
			import(args.merge(:data => data))
		end

	end

	# A dispatcher method that figures out the data's file type,
	# and sends it off to the appropriate importer. Note that
	# import_file_detect will raise an error if the filetype
	# is unknown.
	def import(args={}, &block)
		data = args[:data] || args['data']
		wspace = args[:wspace] || args['wspace'] || workspace
		unless data.kind_of? Zip::ZipFile
			di = data.index("\n")
			raise DBImportError.new("Could not automatically determine file type") if not di
		end
		ftype = import_filetype_detect(data)
		yield(:filetype, @import_filedata[:type]) if block
		self.send "import_#{ftype}".to_sym, args, &block
	end


	# Returns one of: :nexpose_simplexml :nexpose_rawxml :nmap_xml :openvas_xml
	# :nessus_xml :nessus_xml_v2 :qualys_xml :msfe_xml :nessus_nbe :amap_mlog
	# :amap_log :ip_list, :msfx_zip
	# If there is no match, an error is raised instead.
	def import_filetype_detect(data)
		if data.kind_of? Zip::ZipFile
			@import_filedata ||= {}
			@import_filedata[:zip_filename] = File.split(data.to_s).last
			@import_filedata[:zip_basename] = @import_filedata[:zip_filename].gsub(/\.zip$/,"")
			@import_filedata[:zip_entry_names] = data.entries.map {|x| x.name}
			@import_filedata[:zip_xml] = @import_filedata[:zip_entry_names].grep(/^(.*)_[0-9]+\.xml$/).first
			@import_filedata[:zip_wspace] = $1
			@import_filedata[:type] = "Metasploit Express ZIP Report"
			return :msfx_zip if @import_filedata[:zip_xml]
		end
		di = data.index("\n")
		firstline = data[0, di]
		@import_filedata ||= {}
		if (firstline.index("<NeXposeSimpleXML"))
			@import_filedata[:type] = "NeXpose Simple XML"
			return :nexpose_simplexml
		elsif (firstline.index("<NexposeReport"))
			@import_filedata[:type] = "NeXpose XML Report"
			return :nexpose_rawxml
		elsif (firstline.index("<?xml"))
			# it's xml, check for root tags we can handle
			line_count = 0
			data.each_line { |line|
				line =~ /<([a-zA-Z0-9\-\_]+)[ >]/
				case $1
				when "nmaprun"
					@import_filedata[:type] = "Nmap XML"
					return :nmap_xml
				when "openvas-report"
					@import_filedata[:type] = "OpenVAS Report"
					return :openvas_xml
				when "NessusClientData"
					@import_filedata[:type] = "Nessus XML (v1)"
					return :nessus_xml
				when "NessusClientData_v2"
					@import_filedata[:type] = "Nessus XML (v2)"
					return :nessus_xml_v2
				when "SCAN"
					@import_filedata[:type] = "Qualys XML"
					return :qualys_xml
				when /MetasploitExpressV[123]/
					@import_filedata[:type] = "Metasploit Express XML"
					return :msfe_xml
				else
					# Give up if we haven't hit the root tag in the first few lines
					break if line_count > 10
				end
				line_count += 1
			}
		elsif (firstline.index("timestamps|||scan_start"))
			@import_filedata[:type] = "Nessus NBE Report"
			# then it's a nessus nbe
			return :nessus_nbe
		elsif (firstline.index("# amap v"))
			# then it's an amap mlog
			@import_filedata[:type] = "Amap Log -m"
			return :amap_mlog
		elsif (firstline.index("amap v"))
			# then it's an amap log
			@import_filedata[:type] = "Amap Log"
			return :amap_log
		elsif (firstline =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
			# then its an IP list
			@import_filedata[:type] = "IP Address List"
			return :ip_list
		end
		raise DBImportError.new("Could not automatically determine file type")
	end

	# Boils down the validate_import_file to a boolean
	def validate_import_file(data)
		begin
			import_filetype_detect(data)
		rescue DBImportError
			return false
		end
		return true
	end

	#
	# Nexpose Simple XML
	#
	# XXX At some point we'll want to make this a stream parser for dealing
	# with large results files
	#
	def import_nexpose_simplexml_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		import_nexpose_simplexml(args.merge(:data => data))
	end

	# Import a Metasploit Express XML file.
	def import_msfe_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		import_msfe_xml(args.merge(:data => data))
	end

	# Import a Metasploit Express ZIP file. Note that this requires
	# a fair bit of filesystem manipulation, and is very much tied
	# up with the Metasploit Express ZIP file format export (for
	# obvious reasons). In the event directories exist, they will
	# be reused. If target files exist, they will be overwritten.
	#
	# XXX: Refactor so it's not quite as sanity-blasting.
	def import_msfx_zip(args={}, &block)
		data = args[:data]
		wpsace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		new_tmp = File.join(Dir::tmpdir,"msfx",@import_filedata[:zip_basename])
		if File.exists? new_tmp
			unless (File.directory?(new_tmp) && File.writable?(new_tmp))
				raise DBImportError.new("Could not extract zip file to #{new_tmp}")
			end
		else
			FileUtils.mkdir_p(new_tmp)
		end
		@import_filedata[:zip_tmp] = new_tmp

		@import_filedata[:zip_tmp_subdirs] = @import_filedata[:zip_entry_names].map {|x| File.split(x)}.map {|x| x[0]}.uniq.reject {|x| x == "."}

		@import_filedata[:zip_tmp_subdirs].each {|sub|
			tmp_subdirs = File.join(@import_filedata[:zip_tmp],sub)
			if File.exists? tmp_subdirs
				unless (File.directory?(tmp_subdirs) && File.writable?(tmp_subdirs))
					raise DBImportError.new("Could not extract zip file to #{tmp_subdirs}")
				end
			else
				FileUtils.mkdir(tmp_subdirs)
			end
		}

		data.entries.each do |e|
			target = File.join(@import_filedata[:zip_tmp],e.name)
			File.unlink target if File.exists?(target) # Yep. Deleted.
			data.extract(e,target)
			if target =~ /^.*.xml$/
				@import_filedata[:zip_extracted_xml] = target
			end
		end

		# This will kick the newly-extracted XML file through
		# the import_file process all over again.
		if @import_filedata[:zip_extracted_xml]
			new_args = args.dup
			new_args[:filename] = @import_filedata[:zip_extracted_xml]
			new_args[:data] = nil
			new_args[:ifd] = @import_filedata.dup
			if block
				import_file(new_args, &block)
			else
				import_file(new_args)
			end
		end

		# Kick down to all the MSFX ZIP specific items
		if block
			import_msfx_collateral(new_args, &block)
		else
			import_msfx_collateral(new_args)
		end
	end

	# Imports loot, tasks, and reports from an MSFX ZIP reprot.
	# XXX: This function is stupidly long. It needs to be refactored.
	def import_msfx_collateral(args={}, &block)
		data = File.open(args[:filename], "r") {|f| f.read(f.stat.size)}
		wspace = args[:wspace] || args['wspace'] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
		basedir = args[:basedir] || args['basedir'] || File.join(Msf::Config.install_root, "data", "msfx")

		allow_yaml = false

		doc = rexmlify(data)
		if doc.elements["MetasploitExpressV1"]
			m_ver = 1
			allow_yaml = true
		elsif doc.elements["MetasploitExpressV2"]
			m_ver = 2
			allow_yaml = true
		elsif doc.elements["MetasploitExpressV3"]
			m_ver = 3
		else
			m_ver = nil
		end
		unless m_ver
			raise DBImportError.new("Unknown verion for MetasploitExpress XML document")
		end

		host_info = {}
		doc.elements.each("/MetasploitExpressV#{m_ver}/hosts/host") do |host|
			host_info[host.elements["id"].text.to_s.strip] = host.elements["address"].text.to_s.strip
		end

		# Import Loot
		doc.elements.each("/MetasploitExpressV#{m_ver}/loots/loot") do |loot|
			next if bl.include? host_info[loot.elements["host-id"].text.to_s.strip]
			loot_info = {}
			loot_info[:host] = host_info[loot.elements["host-id"].text.to_s.strip]
			loot_info[:workspace] = args[:wspace]
			loot_info[:ctype] = loot.elements["content-type"].text.to_s.strip
			loot_info[:info] = unserialize_object(loot.elements["info"].text.to_s.strip, allow_yaml)
			loot_info[:ltype] = loot.elements["ltype"].text.to_s.strip
			loot_info[:name] = loot.elements["name"].text.to_s.strip
			loot_info[:created_at] = loot.elements["created-at"].text.to_s.strip
			loot_info[:updated_at] = loot.elements["updated-at"].text.to_s.strip
			loot_info[:name] = loot.elements["name"].text.to_s.strip
			loot_info[:orig_path] = loot.elements["path"].text.to_s.strip
			tmp = args[:ifd][:zip_tmp]
			loot_info[:orig_path].gsub!(/^\./,tmp)
			if loot.elements["service-id"].text.to_s.strip.size > 0
				loot_info[:service] = loot.elements["service-id"].text.to_s.strip
			end

			# Only report loot if we actually have it.
			# TODO: Copypasta. Seperate this out.
			if File.exists? loot_info[:orig_path]
				loot_dir = File.join(basedir,"loot")
				loot_file = File.split(loot_info[:orig_path]).last
				if File.exists? loot_dir
					unless (File.directory?(loot_dir) && File.writable?(loot_dir))
						raise DBImportError.new("Could not move files to #{loot_dir}")
					end
				else
					FileUtils.mkdir_p(loot_dir)
				end
				new_loot = File.join(loot_dir,loot_file)
				loot_info[:path] = new_loot
				if File.exists?(new_loot)
					File.unlink new_loot # Delete it, and don't report it.
				else
					report_loot(loot_info) # It's new, so report it.
				end
				FileUtils.copy(loot_info[:orig_path], new_loot)
				yield(:msfx_loot, new_loot) if block
			end
		end

		# Import Tasks
		doc.elements.each("/MetasploitExpressV#{m_ver}/tasks/task") do |task|
			task_info = {}
			task_info[:workspace] = args[:wspace]
			# Should user be imported (original) or declared (the importing user)?
			task_info[:user] = task.elements["created-by"].text.to_s.strip
			task_info[:desc] = task.elements["description"].text.to_s.strip
			task_info[:info] = unserialize_object(task.elements["info"].text.to_s.strip, allow_yaml)
			task_info[:mod] = task.elements["module"].text.to_s.strip
			task_info[:options] = task.elements["options"].text.to_s.strip
			task_info[:prog] = task.elements["progress"].text.to_i
			task_info[:created_at] = task.elements["created-at"].text.to_s.strip
			task_info[:updated_at] = task.elements["updated-at"].text.to_s.strip
			if !task.elements["completed-at"].text.to_s.empty?
				task_info[:completed_at] = task.elements["completed-at"].text.to_s.strip
			end
			if !task.elements["error"].text.to_s.empty?
				task_info[:error] = task.elements["error"].text.to_s.strip
			end
			if !task.elements["result"].text.to_s.empty?
				task_info[:result] = task.elements["result"].text.to_s.strip
			end
			task_info[:orig_path] = task.elements["path"].text.to_s.strip
			tmp = args[:ifd][:zip_tmp]
			task_info[:orig_path].gsub!(/^\./,tmp)

			# Only report a task if we actually have it.
			# TODO: Copypasta. Seperate this out.
			if File.exists? task_info[:orig_path]
				tasks_dir = File.join(basedir,"tasks")
				task_file = File.split(task_info[:orig_path]).last
				if File.exists? tasks_dir
					unless (File.directory?(tasks_dir) && File.writable?(tasks_dir))
						raise DBImportError.new("Could not move files to #{tasks_dir}")
					end
				else
					FileUtils.mkdir_p(tasks_dir)
				end
				new_task = File.join(tasks_dir,task_file)
				task_info[:path] = new_task
				if File.exists?(new_task)
					File.unlink new_task # Delete it, and don't report it.
				else
					report_task(task_info) # It's new, so report it.
				end
				FileUtils.copy(task_info[:orig_path], new_task)
				yield(:msfx_task, new_task) if block
			end
		end

		# Import Reports
		doc.elements.each("/MetasploitExpressV#{m_ver}/reports/report") do |report|
			report_info = {}
			report_info[:workspace] = args[:wspace]
			# Should user be imported (original) or declared (the importing user)?
			report_info[:user] = report.elements["created-by"].text.to_s.strip
			report_info[:options] = report.elements["options"].text.to_s.strip
			report_info[:rtype] = report.elements["rtype"].text.to_s.strip
			report_info[:created_at] = report.elements["created-at"].text.to_s.strip
			report_info[:updated_at] = report.elements["updated-at"].text.to_s.strip

			report_info[:orig_path] = report.elements["path"].text.to_s.strip
			tmp = args[:ifd][:zip_tmp]
			report_info[:orig_path].gsub!(/^\./,tmp)

			# Only report a report if we actually have it.
			# TODO: Copypasta. Seperate this out.
			if File.exists? report_info[:orig_path]
				reports_dir = File.join(basedir,"reports")
				report_file = File.split(report_info[:orig_path]).last
				if File.exists? reports_dir
					unless (File.directory?(reports_dir) && File.writable?(reports_dir))
						raise DBImportError.new("Could not move files to #{reports_dir}")
					end
				else
					FileUtils.mkdir_p(reports_dir)
				end
				new_report = File.join(reports_dir,report_file)
				report_info[:path] = new_report
				if File.exists?(new_report)
					File.unlink new_report
				else
					report_report(report_info)
				end
				FileUtils.copy(report_info[:orig_path], new_report)
				yield(:msfx_report, new_report) if block
			end
		end

	end

	# For each host, step through services, notes, and vulns, and import
	# them.
	# TODO: loot, tasks, and reports
	def import_msfe_xml(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		allow_yaml = false

		doc = rexmlify(data)
		if doc.elements["MetasploitExpressV1"]
			m_ver = 1
			allow_yaml = true
		elsif doc.elements["MetasploitExpressV2"]
			m_ver = 2
			allow_yaml = true
		elsif doc.elements["MetasploitExpressV3"]
			m_ver = 3
		else
			m_ver = nil
		end
		unless m_ver
			raise DBImportError.new("Unknown verion for MetasploitExpress XML document")
		end

		doc.elements.each("/MetasploitExpressV#{m_ver}/hosts/host") do |host|
			host_data = {}
			host_data[:workspace] = wspace
			host_data[:host] = host.elements["address"].text.to_s.strip
			if bl.include? host_data[:host]
				next
			else
				yield(:address,host_data[:host]) if block
			end
			host_data[:host_mac] = host.elements["mac"].text.to_s.strip
			if host.elements["comm"].text
				host_data[:comm] = host.elements["comm"].text.to_s.strip
			end
			%w{created-at updated-at name state os-flavor os-lang os-name os-sp purpose}.each { |datum|
				if host.elements[datum].text
					host_data[datum.gsub('-','_')] = host.elements[datum].text.to_s.strip
				end
			}
			host_address = host_data[:host].dup # Preserve after report_host() deletes
			report_host(host_data)
			host.elements.each('services/service') do |service|
				service_data = {}
				service_data[:workspace] = wspace
				service_data[:host] = host_address
				service_data[:port] = service.elements["port"].text.to_i
				service_data[:proto] = service.elements["proto"].text.to_s.strip
				%w{created-at updated-at name state info}.each { |datum|
					if service.elements[datum].text
						if datum == "info"
							service_data["info"] = unserialize_object(service.elements[datum].text.to_s.strip, false)
						else
							service_data[datum.gsub("-","_")] = service.elements[datum].text.to_s.strip
						end
					end
				}
				report_service(service_data)
			end
			host.elements.each('notes/note') do |note|
				note_data = {}
				note_data[:workspace] = wspace
				note_data[:host] = host_address
				note_data[:type] = note.elements["ntype"].text.to_s.strip
				note_data[:data] = unserialize_object(note.elements["data"].text.to_s.strip, allow_yaml)

				if note.elements["critical"].text
					note_data[:critical] = true
				end
				if note.elements["seen"].text
					note_data[:seen] = true
				end
				%w{created-at updated-at}.each { |datum|
					if note.elements[datum].text
						note_data[datum.gsub("-","_")] = note.elements[datum].text.to_s.strip
					end
				}
				report_note(note_data)
			end
			host.elements.each('vulns/vuln') do |vuln|
				vuln_data = {}
				vuln_data[:workspace] = wspace
				vuln_data[:host] = host_address
				if vuln.elements["info"].text
					vuln_data[:info] = YAML.load(vuln.elements["info"].text.to_s.strip)
				end
				vuln_data[:name] = vuln.elements["name"].text.to_s.strip
				%w{created-at updated-at}.each { |datum|
					if vuln.elements[datum].text
						vuln_data[datum.gsub("-","_")] = vuln.elements[datum].text.to_s.strip
					end
				}
				report_vuln(vuln_data)
			end
			host.elements.each('creds/cred') do |cred|
				cred_data = {}
				cred_data[:workspace] = wspace
				cred_data[:host] = host_address
				%w{port ptype sname proto proof active user pass}.each {|datum|
					if cred.elements[datum].respond_to? :text
						cred_data[datum.intern] = cred.elements[datum].text.to_s.strip
					end
				}
				%w{created-at updated-at}.each { |datum|
					if cred.elements[datum].respond_to? :text
						cred_data[datum.gsub("-","_")] = cred.elements[datum].text.to_s.strip
					end
				}
				if cred_data[:pass] == "<masked>"
					cred_data[:pass] = ""
					cred_data[:active] = false
				elsif cred_data[:pass] == "*BLANK PASSWORD*"
					cred_data[:pass] = ""
				end
				report_cred(cred_data.merge(:wait => true))
			end
		end
	end

	def import_nexpose_simplexml(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		doc = rexmlify(data)
		doc.elements.each('/NeXposeSimpleXML/devices/device') do |dev|
			addr = dev.attributes['address'].to_s
			if bl.include? addr
				next
			else
				yield(:address,addr) if block
			end

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
				:state     => Msf::HostState::Alive
			}

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
					:info      => vid,
					:refs      => refs)
			end

			# Load the services
			dev.elements.each('services/service') do |svc|
				sname = svc.attributes['name'].to_s
				sprot = svc.attributes['protocol'].to_s.downcase
				sport = svc.attributes['port'].to_s.to_i
				next if sport == 0

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
						:info => vid,
						:refs => refs)
				end
			end
		end
	end


	#
	# Nexpose Raw XML
	#
	def import_nexpose_rawxml_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		import_nexpose_rawxml(args.merge(:data => data))
	end

	def import_nexpose_rawxml(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		# Use a stream parser instead of a tree parser so we can deal with
		# huge results files without running out of memory.
		parser = Rex::Parser::NexposeXMLStreamParser.new

		# Since all the Refs have to be in the database before we can use them
		# in a Vuln, we store all the hosts until we finish parsing and only
		# then put everything in the database.  This is memory-intensive for
		# large files, but should be much less so than a tree parser.
		#
		# This method is also considerably faster than parsing through the tree
		# looking for references every time we hit a vuln.
		hosts = []
		vulns = []

		# The callback merely populates our in-memory table of hosts and vulns
		parser.callback = Proc.new { |type, value|
			case type
			when :host
				hosts.push(value)
			when :vuln
				vulns.push(value)
			end
		}

		REXML::Document.parse_stream(data, parser)

		vuln_refs = nexpose_refs_to_hash(vulns)
		hosts.each do |host|
			if bl.include? host["addr"]
				next
			else
				yield(:address,host["addr"]) if block
				#
			end
			nexpose_host(host, vuln_refs, wspace)
		end
	end

	#
	# Takes an array of vuln hashes, as returned by the NeXpose rawxml stream
	# parser, like:
	#   [
	#		{"id"=>"winreg-notes-protocol-handler", severity="8", "refs"=>[{"source"=>"BID", "value"=>"10600"}, ...]}
	#		{"id"=>"windows-zotob-c", severity="8", "refs"=>[{"source"=>"BID", "value"=>"14513"}, ...]}
	#	]
	# and transforms it into a hash of vuln references keyed on vuln id, like:
	#	{ "windows-zotob-c" => [{"source"=>"BID", "value"=>"14513"}, ...] }
	#
	# This method ignores all attributes other than the vuln's NeXpose ID and
	# references (including title, severity, et cetera).
	#
	def nexpose_refs_to_hash(vulns)
		refs = {}
		vulns.each do |vuln|
			vuln["refs"].each do |ref|
				refs[vuln['id']] ||= []
				if ref['source'] == 'BID'
					refs[vuln['id']].push('BID-' + ref["value"])
				elsif ref['source'] == 'CVE'
					# value is CVE-$ID
					refs[vuln['id']].push(ref["value"])
				elsif ref['source'] == 'MS'
					refs[vuln['id']].push('MSB-MS-' + ref["value"])
				elsif ref['source'] == 'URL'
					refs[vuln['id']].push('URL-' + ref["value"])
				#else
				#	$stdout.puts("Unknown source: #{ref["source"]}")
				end
			end
		end
		refs
	end

	def nexpose_host(h, vuln_refs, wspace)
		data = {:workspace => wspace}
		if h["addr"]
			addr = h["addr"]
		else
			# Can't report it if it doesn't have an IP
			return
		end
		data[:host] = addr
		if (h["hardware-address"])
			# Put colons between each octet of the MAC address
			data[:mac] = h["hardware-address"].gsub(':', '').scan(/../).join(':')
		end
		data[:state] = (h["status"] == "alive") ? Msf::HostState::Alive : Msf::HostState::Dead

		# Since we only have one name field per host in the database, just
		# take the first one.
		if (h["names"] and h["names"].first)
			data[:name] = h["names"].first
		end

		if (data[:state] != Msf::HostState::Dead)
			report_host(data)
		end

		if h["os_family"]
			note = {
				:workspace => wspace,
				:host => addr,
				:type => 'host.os.nexpose_fingerprint',
				:data => {
					:family    => h["os_family"],
					:certainty => h["os_certainty"]
				}
			}
			note[:data][:vendor]  = h["os_vendor"]  if h["os_vendor"]
			note[:data][:product] = h["os_product"] if h["os_product"]
			note[:data][:arch]    = h["arch"]       if h["arch"]

			report_note(note)
		end

		h["endpoints"].each { |p|
			extra = ""
			extra << p["product"] + " " if p["product"]
			extra << p["version"] + " " if p["version"]

			# Skip port-0 endpoints
			next if p["port"].to_i == 0

			# XXX This should probably be handled in a more standard way
			# extra << "(" + p["certainty"] + " certainty) " if p["certainty"]

			data = {}
			data[:workspace] = wspace
			data[:proto] = p["protocol"].downcase
			data[:port]  = p["port"].to_i
			data[:state] = p["status"]
			data[:host]  = addr
			data[:info]  = extra if not extra.empty?
			if p["name"] != "<unknown>"
				data[:name] = p["name"]
			end
			report_service(data)
		}

		h["vulns"].each_pair { |k,v|
			next if v["status"] != "vulnerable-exploited" and v["status"] != "vulnerable-version"

			data = {}
			data[:workspace] = wspace
			data[:host] = addr
			data[:proto] = v["protocol"].downcase if v["protocol"]
			data[:port] = v["port"].to_i if v["port"]
			data[:name] = "NEXPOSE-" + v["id"]
			data[:refs] = vuln_refs[v["id"]]
			report_vuln(data)
		}
	end

	#
	# Import Nmap's -oX xml output
	#
	def import_nmap_xml_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		import_nmap_xml(args.merge(:data => data))
	end

	def import_nmap_xml(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
		fix_services = args[:fix_services]

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
				raise RuntimeError, "At least one IPv4 or IPv6 address is required"
			end
			next if bl.include? addr
			data[:host] = addr
			if (h["addrs"].has_key?("mac"))
				data[:mac] = h["addrs"]["mac"]
			end
			data[:state] = (h["status"] == "up") ? Msf::HostState::Alive : Msf::HostState::Dead

			if ( h["reverse_dns"] )
				data[:name] = h["reverse_dns"]
			end

			# Only report alive hosts with ports to speak of.
			if(data[:state] != Msf::HostState::Dead)
				if h["ports"].size > 0
					if fix_services
						port_states = h["ports"].map {|p| p["state"]}.reject {|p| p == "filtered"}
						next if port_states.compact.empty?
					end
					yield(:address,data[:host]) if block
					report_host(data)
					report_import_note(wspace,addr)
				end
			end

			if( h["os_vendor"] )
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
				# Localhost port results are pretty unreliable -- if it's
				# unknown, it's no good (possibly Windows-only)
				if (
					p["state"] == "unknown" &&
					h["status_reason"] == "localhost-response"
				)
					next
				end
				extra = ""
				extra << p["product"]   + " " if p["product"]
				extra << p["version"]   + " " if p["version"]
				extra << p["extrainfo"] + " " if p["extrainfo"]

				data = {}
				data[:workspace] = wspace
				if fix_services
					data[:proto] = nmap_msfx_service_map(p["protocol"])
				else
					data[:proto] = p["protocol"].downcase
				end
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

	def nmap_msfx_service_map(proto)
		return proto unless proto.kind_of? String
		case proto.downcase
		when "msrpc", "nfs-or-iis";         "dcerpc"
		when "netbios-ns";                  "netbios"
		when "netbios-ssn", "microsoft-ds"; "smb"
		when "ms-sql-s";                    "mssql"
		when "ms-sql-m";                    "mssql-m"
		when "postgresql";                  "postgres"
		when "http-proxy";                  "http"
		when "iiimsf";                      "db2"
		else
			proto.downcase
		end
	end

	def report_import_note(wspace,addr)
		if @import_filedata.kind_of?(Hash) && @import_filedata[:filename] && @import_filedata[:filename] !~ /msfe-nmap[0-9]{8}/
		report_note(
			:workspace => wspace,
			:host => addr,
			:type => 'host.imported',
			:data => @import_filedata.merge(:time=> Time.now.utc)
		)
		end
	end

	#
	# Import Nessus NBE files
	#
	def import_nessus_nbe_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		import_nessus_nbe(args.merge(:data => data))
	end

	def import_nessus_nbe(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		nbe_copy = data.dup
		# First pass, just to build the address map.
		addr_map = {}

		nbe_copy.each_line do |line|
			r = line.split('|')
			next if r[0] != 'results'
			next if r[4] != "12053"
			data = r[6]
			addr,hname = data.match(/([0-9\x2e]+) resolves as (.+)\x2e\\n/)[1,2]
			addr_map[hname] = addr
		end

		data.each_line do |line|
			r = line.split('|')
			next if r[0] != 'results'
			hname = r[2]
			if addr_map[hname]
				addr = addr_map[hname]
			else
				addr = hname # Must be unresolved, probably an IP address.
			end
			port = r[3]
			nasl = r[4]
			type = r[5]
			data = r[6]

			# If there's no resolution, or if it's malformed, skip it.
			next unless ipv4_validator(addr)

			if bl.include? addr
				next
			else
				yield(:address,addr) if block
			end

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
			if nasl == "11936"
				os = data.match(/The remote host is running (.*)\\n/)[1]
				report_note(
					:workspace => wspace,
					:host => addr,
					:type => 'host.os.nessus_fingerprint',
					:data => {
						:os => os.to_s.strip
					}
				)
			end
			handle_nessus(wspace, addr, port, nasl, severity, data)
		end
	end

	#
	# Of course they had to change the nessus format.
	#
	def import_openvas_xml(args={}, &block)
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		raise DBImportError.new("No OpenVAS XML support. Please submit a patch to msfdev[at]metasploit.com")
	end

	#
	# Import Nessus XML v1 and v2 output
	#
	# Old versions of openvas exported this as well
	#
	def import_nessus_xml_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)

		if data.index("NessusClientData_v2")
			import_nessus_xml_v2(args.merge(:data => data))
		else
			import_nessus_xml(args.merge(:data => data))
		end
	end

	def import_nessus_xml(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		doc = rexmlify(data)
		doc.elements.each('/NessusClientData/Report/ReportHost') do |host|

			addr = nil
			hname = nil
			os = nil
			# If the name is resolved, the Nessus plugin for DNS
			# resolution should be there. If not, fall back to the
			# HostName
			host.elements.each('ReportItem') do |item|
				next unless item.elements['pluginID'].text == "12053"
				addr = item.elements['data'].text.match(/([0-9\x2e]+) resolves as/)[1]
				hname = host.elements['HostName'].text
			end
			addr ||= host.elements['HostName'].text
			next unless ipv4_validator(addr) # Skip resolved names and SCAN-ERROR.
			if bl.include? addr
				next
			else
				yield(:address,addr) if block
			end

			hinfo = {
				:workspace => wspace,
				:host => addr
			}

			# Record the hostname
			hinfo.merge!(:name => hname.to_s.strip) if hname
			report_host(hinfo)

			# Record the OS
			os ||= host.elements["os_name"]
			if os
				report_note(
					:workspace => wspace,
					:host => addr,
					:type => 'host.os.nessus_fingerprint',
					:data => {
						:os => os.text.to_s.strip
					}
				)
			end

			host.elements.each('ReportItem') do |item|
				nasl = item.elements['pluginID'].text
				port = item.elements['port'].text
				data = item.elements['data'].text
				severity = item.elements['severity'].text

				handle_nessus(wspace, addr, port, nasl, severity, data)
			end
		end
	end

	def import_nessus_xml_v2(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		doc = rexmlify(data)
		doc.elements.each('/NessusClientData_v2/Report/ReportHost') do |host|
			# if Nessus resovled the host, its host-ip tag should be set
			# otherwise, fall back to the name attribute which would
			# logically need to be an IP address
			begin
				addr = host.elements["HostProperties/tag[@name='host-ip']"].text
			rescue
				addr = host.attribute("name").value
			end

			next unless ipv4_validator(addr) # Catches SCAN-ERROR, among others.
			if bl.include? addr
				next
			else
				yield(:address,addr) if block
			end

			os = host.elements["HostProperties/tag[@name='operating-system']"]
			if os
				report_note(
					:workspace => wspace,
					:host => addr,
					:type => 'host.os.nessus_fingerprint',
					:data => {
						:os => os.text.to_s.strip
					}
				)
			end

			hname = host.elements["HostProperties/tag[@name='host-fqdn']"]
			if hname
				report_host(
					:workspace => wspace,
					:host => addr,
					:name => hname.text.to_s.strip
				)
			end

			mac = host.elements["HostProperties/tag[@name='mac-address']"]
			if mac
				report_host(
					:workspace => wspace,
					:host => addr,
					:mac  => mac.text.to_s.strip.upcase
				)
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

	#
	# Import Qualys' xml output
	#
	def import_qualys_xml_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		import_qualys_xml(args.merge(:data => data))
	end

	def import_qualys_xml(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []


		doc = rexmlify(data)
		doc.elements.each('/SCAN/IP') do |host|
			addr  = host.attributes['value']
			if bl.include? addr
				next
			else
				yield(:address,addr) if block
			end
			hname = host.attributes['name'] || ''

			report_host(:workspace => wspace, :host => addr, :name => hname, :state => Msf::HostState::Alive)

			if host.elements["OS"]
				hos = host.elements["OS"].text
				report_note(
					:workspace => wspace,
					:host => addr,
					:type => 'host.os.qualys_fingerprint',
					:data => {
						:os => hos
					}
				)
			end

			# Open TCP Services List (Qualys ID 82023)
			services_tcp = host.elements["SERVICES/CAT/SERVICE[@number='82023']/RESULT"]
			if services_tcp
				services_tcp.text.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
					if match[2] == nil or match[2].strip == 'unknown'
						name = match[1].strip
					else
						name = match[2].strip
					end
					handle_qualys(wspace, addr, match[0].to_s, 'tcp', 0, nil, nil, name)
				end
			end
			# Open UDP Services List (Qualys ID 82004)
			services_udp = host.elements["SERVICES/CAT/SERVICE[@number='82004']/RESULT"]
			if services_udp
				services_udp.text.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
					if match[2] == nil or match[2].strip == 'unknown'
						name = match[1].strip
					else
						name = match[2].strip
					end
					handle_qualys(wspace, addr, match[0].to_s, 'udp', 0, nil, nil, name)
				end
			end

			# VULNS are confirmed, PRACTICES are unconfirmed vulnerabilities
			host.elements.each('VULNS/CAT | PRACTICES/CAT') do |cat|
				port = cat.attributes['port']
				protocol = cat.attributes['protocol']
				cat.elements.each('VULN | PRACTICE') do |vuln|
					refs = []
					qid = vuln.attributes['number']
					severity = vuln.attributes['severity']
					vuln.elements.each('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE') do |ref|
						refs.push(ref.elements['ID'].text.to_s)
					end
					vuln.elements.each('CVE_ID_LIST/CVE_ID') do |ref|
						refs.push('CVE-' + /C..-([0-9\-]{9})/.match(ref.elements['ID'].text.to_s)[1])
					end
					vuln.elements.each('BUGTRAQ_ID_LIST/BUGTRAQ_ID') do |ref|
						refs.push('BID-' + ref.elements['ID'].text.to_s)
					end

					handle_qualys(wspace, addr, port, protocol, qid, severity, refs)
				end
			end
		end
	end

	def import_ip_list_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace

		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		import_ip_list(args.merge(:data => data))
	end

	def import_ip_list(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		data.each_line do |ip|
			ip.strip!
			if bl.include? ip
				next
			else
				yield(:address,ip) if block
			end
			host = find_or_create_host(:workspace => wspace, :host=> ip, :state => Msf::HostState::Alive)
		end
	end

	def import_amap_log_file(args={})
		filename = args[:filename]
		wspace = args[:wspace] || workspace
		f = File.open(filename, 'rb')
		data = f.read(f.stat.size)
		case import_filetype_detect(data)
		when :amap_log
			import_amap_log(args.merge(:data => data))
		when :amap_mlog
			import_amap_mlog(args.merge(:data => data))
		else
			raise DBImportError.new("Could not determine file type")
		end
	end

	def import_amap_log(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		data.each_line do |line|
			next if line =~ /^#/
			next if line !~ /^Protocol on ([^:]+):([^\x5c\x2f]+)[\x5c\x2f](tcp|udp) matches (.*)$/
			addr   = $1
			next if bl.include? addr
			port   = $2.to_i
			proto  = $3.downcase
			name   = $4
			host = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)
			next if not host
			yield(:address,addr) if block
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

	def import_amap_mlog(args={}, &block)
		data = args[:data]
		wspace = args[:wspace] || workspace
		bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

		data.each_line do |line|
			next if line =~ /^#/
			r = line.split(':')
			next if r.length < 6

			addr   = r[0]
			next if bl.include? addr
			port   = r[1].to_i
			proto  = r[2].downcase
			status = r[3]
			name   = r[5]
			next if status != "open"

			host = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)
			next if not host
			yield(:address,addr) if block
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

	def unserialize_object(string, allow_yaml = false)
		return string unless string.is_a?(String)
		return nil if not string
		return nil if string.empty?

		begin
			# Validate that it is properly formed base64 first
			if string.gsub(/\s+/, '') =~ /^([a-z0-9A-Z\+\/=]+)$/
				Marshal.load($1.unpack("m")[0])
			else
				if allow_yaml
					YAML.load(string) rescue string
				else
					string
				end
			end
		rescue ::Exception => e
			if allow_yaml
				YAML.load(string) rescue string
			else
				string
			end
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

		vuln_info = {
			:workspace => wspace,
			:host => addr,
			:port => port,
			:proto => proto,
			:name => nss,
			:info => data,
			:refs => refs
		}
		report_vuln(vuln_info)
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

		if port.to_i != 0
			report_service(info)
		end

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

		vuln = {
			:workspace => wspace,
			:host => addr,
			:name => nss,
			:info => description ? description.text : "",
			:refs => refs
		}

		if port.to_i != 0
			vuln[:port]  = port
			vuln[:proto] = proto
		end

		report_vuln(vuln)
	end

	#
	# Qualys report parsing/handling
	#
	def handle_qualys(wspace, addr, port, protocol, qid, severity, refs, name=nil)

		port = port.to_i

		info = { :workspace => wspace, :host => addr, :port => port, :proto => protocol }
		if name and name != 'unknown'
			info[:name] = name
		end

		if info[:host] && info[:port] && info[:proto]
			report_service(info)
		end

		return if qid == 0

		if addr
			report_vuln(
				:workspace => wspace,
				:host => addr,
				:port => port,
				:proto => protocol,
				:name => 'QUALYS-' + qid,
				:refs => refs
			)
		end
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
				:info => title)

			rids = []
			refs.keys.each do |r|
				rids << find_or_create_ref(:name => r)
			end

			vuln.refs << (rids - vuln.refs)
		end
	end

end

end

