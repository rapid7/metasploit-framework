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
	# Deletes a host and associated data matching this address/comm
	#
	def del_host(context, address, comm='')
		host = Host.find(:first, :conditions => ["address = ? and comm = ?", address, comm])

		return unless host

		services = Service.find(:all, :conditions => ["host_id = ?", host.id]).map { |s| s.id }

		services.each do |sid|
			Vuln.delete_all(["service_id = ?", sid])
			Service.delete(sid)
		end

		Note.delete_all(["host_id = ?", host.id])
		Host.delete(host.id)
	end
    
    #
    # Deletes a port and associated vulns matching this port
    #
    def del_service(context, address, proto, port, comm='')
        host = get_host(context, address, comm)

        return unless host

        services = Service.find(:all, :conditions => ["host_id = ? and proto = ? and port = ?", host.id, proto, port]).map { |s| s.id }

        services.each do |sid|
            Vuln.delete_all(["service_id = ?", sid])
            Service.delete(sid)
        end
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
	
	#
	# WMAP
	# Support methods
	#
	
	#
	# WMAP
	# Selected host
	#
	def selected_host
		selhost = Target.find(:first, :conditions => ["selected > 0"] )
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
		Target.find(:first, :conditions => ["selected > 0"] ).port
	end

	#
	# WMAP
	# Selected ssl
	#
	def selected_ssl
		Target.find(:first, :conditions => ["selected > 0"] ).ssl
	end	
	
	#
	# WMAP
	# Selected id
	#
	def selected_id
		Target.find(:first, :conditions => ["selected > 0"] ).object_id
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
		Request.find(:all, :select => 'DISTINCT host,port,ssl')
	end
	
	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_path(&block)
		target_requests('AND requests.path IS NOT NULL').each do |req|
			block.call(req)
		end
	end

	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_query(&block)
		target_requests('AND requests.query IS NOT NULL').each do |req|
			block.call(req)
		end
	end
	
	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_body(&block)
		target_requests('AND requests.body IS NOT NULL').each do |req|
			block.call(req)
		end
	end
	
	#
	# WMAP
	# This method iterates the requests table returning a list of all requests of a specific target
	#
	def each_request_target_with_headers(&block)
		target_requests('AND requests.headers IS NOT NULL').each do |req|
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
		Request.find(:all, :conditions => ["requests.host = ? AND requests.port = ? #{extra_condition}",selected_host,selected_port])
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
		Request.find(:all, :conditions => ["requests.host = ? AND requests.port = ? #{extra_condition}",host,port])
	end
	
	#
	# WMAP
	# This methods returns a list of all targets in the database
	#
	def requests
		Request.find(:all)
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
		Target.find(:all)
	end

	#
	# WMAP
	# This methods deletes all targets from targets table in the database
	#
	def delete_all_targets
		Target.delete_all
	end
	
	#
	# WMAP
	# Find a target matching this id
	#
	def get_target(id)
		target = Target.find(:first, :conditions => [ "id = ?", id])
		return target
	end
	
	#
	# WMAP
	# Create a target 
	#
	def create_target(host,port,ssl,sel)
		tar = Target.create(
				:host => host, 
				:port => port, 
				:ssl => ssl, 
				:selected => sel
			)
		tar.save	
		#framework.events.on_db_target(context, rec)
	end
	
	#
	# WMAP
	# Store data in report table
	# First attempt for reporting. parent_id to point to other report entries
	# to define context.
	#
	#
	def create_report(parent_id,entity,etype,value,notes,source)
		rep = Report.create(
				:target_id => self.selected_id,
				:parent_id => parent_id, 
				:entity => entity, 
				:etype => etype, 
				:value => value,
				:notes => notes,
				:source => source,
				:created => Time.now
			)
		rep.save

		return rep.id	
		#framework.events.on_db_target(context, rec)
	end

	#
	# WMAP
	# Last report available for the target to store new report entries.
	#
	def last_report_id(host,port,ssl)
		rep = Report.find(:first, :order => 'id desc', :conditions => [ "parent_id = ? and value = ?",0,"#{host},#{port},#{ssl}"])		
		
		if (not rep)
			rep_id = framework.db.create_report(0,'WMAP','REPORT',"#{host},#{port},#{ssl}","Metasploit WMAP Report",'WMAP Scanner')
		else
			rep_id = rep.id
		end	

		return rep_id
	end
	
	#
	# WMAP
	# Quick way to identify if the report database is available
	#
	def report_active?
		begin
			Report.table_exists?
		rescue
			false
		end
	end
	
	#
	# WMAP
	# This method iterates the reports table to list available reports
	#
	def each_report(&block)
		Report.find(:all, :order => 'id desc', :conditions => [ "entity =? and etype=?",'WMAP','REPORT']).each do |report|
			block.call(report)
		end
	end
	
	#
	# WMAP
	# This scary method iterates the reports table parent
	#
	def report_parent(id) 
		Report.find(id)			
	end
	
	#
	# WMAP
	# This scary method iterates the reports table children
	#
	def report_children(parent_id) 
		Report.find(:all, :conditions => ["parent_id=?",parent_id])			
	end
	
	#
	# WMAP
	# This method allows to query directly the reports table. To be used mainly by modules
	# Not tied to a specific report to be able to use data from other targets.
	#
	def report_sql(condition)
		Report.find(:all, :conditions => ["#{condition}"])
	end
	
	#
	# WMAP
	# Create a request (by hand) 
	#
	def create_request(host,port,ssl,meth,path,headers,query,body,respcode,resphead,response)
		req = Request.create(
				:host => host, 
				:port => port, 
				:ssl => ssl, 
				:meth => meth,
				:path => path,
				:headers => headers,
				:query => query,
				:body => body,
				:respcode => respcode,
				:resphead => resphead,
				:response => response,
				:created => Time.now
			)
		req.save	
		#framework.events.on_db_request(context, rec)
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
