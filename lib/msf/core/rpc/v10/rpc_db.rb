# -*- coding: binary -*-
module Msf
module RPC
class RPC_Db < RPC_Base

private
  def db
    self.framework.db.connected?
  end

  def find_workspace(wspace = nil)
    if(wspace and wspace != "")
      return self.framework.db.find_workspace(wspace) || error(500, "Invalid workspace")
    end
    self.framework.db.workspace
  end

  def fix_options(opts)
    newopts = {}
    opts.each do |k,v|
      newopts[k.to_sym] = v
    end
    newopts
  end

  def opts_to_hosts(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = find_workspace(opts[:workspace])
    hosts  = []
    if opts[:host] or opts[:address]
      host = opts[:host] || opts[:address]
      hent = wspace.hosts.find_by_address(host)
      return hosts if hent == nil
      hosts << hent if hent.class == ::Mdm::Host
      hosts |= hent if hent.class == Array
    elsif opts[:addresses]
      return hosts if opts[:addresses].class != Array
      conditions = {}
      conditions[:address] = opts[:addresses]
      hent = wspace.hosts.all(:conditions => conditions)
      hosts |= hent if hent.class == Array
    end
    return hosts
  }
  end

  def opts_to_services(hosts,opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = find_workspace(opts[:workspace])
    services = []
    if opts[:host] or opts[:address] or opts[:addresses]
      return services if hosts.count < 1
      hosts.each do |h|
        if opts[:port] or opts[:proto]
          conditions = {}
          conditions[:port] = opts[:port] if opts[:port]
          conditions[:proto] = opts[:proto] if opts[:proto]
          sret = h.services.all(:conditions => conditions)
          next if sret == nil
          services |= sret if sret.class == Array
          services << sret if sret.class == ::Mdm::Service
        else
          services |= h.services
        end
      end
    elsif opts[:port] or opts[:proto]
      conditions = {}
      conditions[:port] = opts[:port] if opts[:port]
      conditions[:proto] = opts[:proto] if opts[:proto]
      sret = wspace.services.all(:conditions => conditions)
      services |= sret if sret.class == Array
      services << sret if sret.class == ::Mdm::Service
    end
    return services
  }
  end

  def db_check
    error(500, "Database Not Loaded") if not db
  end

  def init_db_opts_workspace(xopts)
    db_check
    opts = fix_options(xopts)
    opts[:workspace] = find_workspace(opts[:workspace])
    return opts, opts[:workspace]
  end

public

  def rpc_hosts(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    conditions = {}
    conditions[:state] = [Msf::HostState::Alive, Msf::HostState::Unknown] if opts[:only_up]
    conditions[:address] = opts[:addresses] if opts[:addresses]

    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    ret = {}
    ret[:hosts] = []
    wspace.hosts.all(:conditions => conditions, :order => :address,
        :limit => limit, :offset => offset).each do |h|
      host = {}
      host[:created_at] = h.created_at.to_i
      host[:address] = h.address.to_s
      host[:mac] = h.mac.to_s
      host[:name] = h.name.to_s
      host[:state] = h.state.to_s
      host[:os_name] = h.os_name.to_s
      host[:os_flavor] = h.os_flavor.to_s
      host[:os_sp] = h.os_sp.to_s
      host[:os_lang] = h.os_lang.to_s
      host[:updated_at] = h.updated_at.to_i
      host[:purpose] = h.purpose.to_s
      host[:info] = h.info.to_s
      ret[:hosts]  << host
    end
    ret
  }
  end

  def rpc_services( xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions[:state] = [ServiceState::Open] if opts[:only_up]
    conditions[:proto] = opts[:proto] if opts[:proto]
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]
    conditions[:port] = Rex::Socket.portspec_to_portlist(opts[:ports]) if opts[:ports]
    conditions[:name] = opts[:names].strip().split(",") if opts[:names]

    ret = {}
    ret[:services] = []

    wspace.services.all(:include => :host, :conditions => conditions,
        :limit => limit, :offset => offset).each do |s|
      service = {}
      host = s.host
      service[:host] = host.address || "unknown"
      service[:created_at] = s[:created_at].to_i
      service[:updated_at] = s[:updated_at].to_i
      service[:port] = s[:port]
      service[:proto] = s[:proto].to_s
      service[:state] = s[:state].to_s
      service[:name] = s[:name].to_s
      service[:info] = s[:info].to_s
      ret[:services] << service
    end
    ret
  }
  end

  def rpc_vulns(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]
    conditions[:name] = opts[:names].strip().split(",") if opts[:names]
    conditions["services.port"] = Rex::Socket.portspec_to_portlist(opts[:ports]) if opts[:port]
    conditions["services.proto"] = opts[:proto] if opts[:proto]

    ret = {}
    ret[:vulns] = []
    wspace.vulns.all(:include => :service, :conditions => conditions, :limit => limit, :offset => offset).each do |v|
      vuln = {}
      reflist = v.refs.map { |r| r.name }
      if(v.service)
        vuln[:port] = v.service.port
        vuln[:proto] = v.service.proto
      else
        vuln[:port] = nil
        vuln[:proto] = nil
      end
      vuln[:time] = v.created_at.to_i
      vuln[:host] = v.host.address || nil
      vuln[:name] = v.name
      vuln[:refs] = reflist.join(',')
      ret[:vulns] << vuln
    end
    ret
  }
  end

  def rpc_workspaces
    db_check

    res = {}
    res[:workspaces] = []
    self.framework.db.workspaces.each do |j|
      ws = {}
      ws[:name] = j.name
      ws[:created_at] = j.created_at.to_i
      ws[:updated_at] = j.updated_at.to_i
      res[:workspaces] << ws
    end
    res
  end

  def rpc_current_workspace
    db_check
    { "workspace" => self.framework.db.workspace.name }
  end

  def rpc_get_workspace(wspace)
    db_check
    wspace = find_workspace(wspace)
    ret = {}
    ret[:workspace] = []
    if(wspace)
      w = {}
      w[:name] = wspace.name
      w[:created_at] = wspace.created_at.to_i
      w[:updated_at] = wspace.updated_at.to_i
      ret[:workspace] << w
    end
    ret
  end

  def rpc_set_workspace(wspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    workspace = self.framework.db.find_workspace(wspace)
    if(workspace)
      self.framework.db.workspace = workspace
      return { 'result' => "success" }
    end
    { 'result' => 'failed' }
  }
  end

  def rpc_del_workspace(wspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    # Delete workspace
    workspace = self.framework.db.find_workspace(wspace)
    if workspace.nil?
      error(404, "Workspace not found: #{wspace}")
    elsif workspace.default?
      workspace.destroy
      workspace = self.framework.db.add_workspace(workspace.name)
    else
      # switch to the default workspace if we're about to delete the current one
      self.framework.db.workspace = self.framework.db.default_workspace if self.framework.db.workspace.name == workspace.name
      # now destroy the named workspace
      workspace.destroy
    end
    { 'result' => "success" }
  }
  end

  def rpc_add_workspace(wspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    wspace = self.framework.db.add_workspace(wspace)
    return { 'result' => 'success' } if(wspace)
    { 'result' => 'failed' }
  }
  end

  def rpc_get_host(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    ret = {}
    ret[:host] = []
    opts = fix_options(xopts)
    h = self.framework.db.get_host(opts)
    if(h)
      host = {}
      host[:created_at] = h.created_at.to_i
      host[:address] = h.address.to_s
      host[:mac] = h.mac.to_s
      host[:name] = h.name.to_s
      host[:state] = h.state.to_s
      host[:os_name] = h.os_name.to_s
      host[:os_flavor] = h.os_flavor.to_s
      host[:os_sp] = h.os_sp.to_s
      host[:os_lang] = h.os_lang.to_s
      host[:updated_at] = h.updated_at.to_i
      host[:purpose] = h.purpose.to_s
      host[:info] = h.info.to_s
      ret[:host] << host
    end
    ret
  }
  end

  def rpc_report_host(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    res = self.framework.db.report_host(opts)
    return { :result => 'success' } if(res)
    { :result => 'failed' }
  }
  end

  def rpc_report_service(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = self.framework.db.report_service(opts)
    return { :result => 'success' } if(res)
    { :result => 'failed' }
  }
  end

  def rpc_get_service(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    ret = {}
    ret[:service] = []

    host = self.framework.db.get_host(opts)

    services = []
    sret = nil

    if(host && opts[:proto] && opts[:port])
      sret = host.services.find_by_proto_and_port(opts[:proto], opts[:port])
    elsif(opts[:proto] && opts[:port])
      conditions = {}
      conditions[:state] = [ServiceState::Open] if opts[:up]
      conditions[:proto] = opts[:proto] if opts[:proto]
      conditions[:port] = opts[:port] if opts[:port]
      conditions[:name] = opts[:names] if opts[:names]
      sret = wspace.services.all(:conditions => conditions, :order => "hosts.address, port")
    else
      sret = host.services
    end
    return ret if sret == nil
    services << sret if sret.class == ::Mdm::Service
    services |= sret if sret.class == Array


    services.each do |s|
      service = {}
      host = s.host
      service[:host] = host.address || "unknown"
      service[:created_at] = s[:created_at].to_i
      service[:updated_at] = s[:updated_at].to_i
      service[:port] = s[:port]
      service[:proto] = s[:proto].to_s
      service[:state] = s[:state].to_s
      service[:name] = s[:name].to_s
      service[:info] = s[:info].to_s
      ret[:service] << service
    end
    ret
  }
  end

  def rpc_get_note(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    ret = {}
    ret[:note] = []

    host = self.framework.db.get_host(opts)

    return ret if( not host)
    notes = []
    if(opts[:proto] && opts[:port])
      services = []
      nret = host.services.find_by_proto_and_port(opts[:proto], opts[:port])
      return ret if nret == nil
      services << nret if nret.class == ::Mdm::Service
      services |= nret if nret.class == Array

      services.each do |s|
        nret = nil
        if opts[:ntype]
          nret = s.notes.find_by_ntype(opts[:ntype])
        else
          nret = s.notes
        end
        next if nret == nil
        notes << nret if nret.class == ::Mdm::Note
        notes |= nret if nret.class == Array
      end
    else
      notes = host.notes
    end
    notes.each do |n|
      note = {}
      host = n.host
      note[:host] = host.address || "unknown"
      if n.service
        note[:port] = n.service.port
        note[:proto] = n.service.proto
      end
      note[:created_at] = n[:created_at].to_i
      note[:updated_at] = n[:updated_at].to_i
      note[:ntype] = n[:ntype].to_s
      note[:data] = n[:data]
      note[:critical] = n[:critical].to_s
      note[:seen] = n[:seen].to_s
      ret[:note] << note
    end
    ret
  }
  end

  def rpc_get_client(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    ret = {}
    ret[:client] = []
    c = self.framework.db.get_client(opts)
    if(c)
      client = {}
      host = c.host
      client[:host] = host.address
      client[:created_at] = c.created_at.to_i
      client[:updated_at] = c.updated_at.to_i
      client[:ua_string] = c.ua_string.to_s
      client[:ua_name] = c.ua_name.to_s
      client[:ua_ver] = c.ua_ver.to_s
      ret[:client] << client
    end
    ret
  }
  end

  def rpc_report_client(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = self.framework.db.report_client(opts)
    return { :result => 'success' } if(res)
    { :result => 'failed' }
  }
  end

  #DOC NOTE: :data and :ntype are REQUIRED
  def rpc_report_note(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    if (opts[:host] or opts[:address]) and opts[:port] and opts[:proto]
      addr = opts[:host] || opts[:address]
      wspace = opts[:workspace] || self.framework.db.workspace
      host = wspace.hosts.find_by_address(addr)
      service = host.services.find_by_proto_and_port(opts[:proto],opts[:port]) if host.services.count > 0
      opts[:service] = service if service
    end

    res = self.framework.db.report_note(opts)
    return { :result => 'success' } if(res)
    { :result => 'failed' }
  }
  end

  def rpc_notes(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]
    conditions[:name] = opts[:names].strip().split(",") if opts[:names]
    conditions[:ntype] = opts[:ntype] if opts[:ntype]
    conditions["services.port"] = Rex::Socket.portspec_to_portlist(opts[:ports]) if opts[:port]
    conditions["services.proto"] = opts[:proto] if opts[:proto]

    ret = {}
    ret[:notes] = []
    wspace.notes.all(:include => [:host, :service], :conditions => conditions,
        :limit => limit, :offset => offset).each do |n|
      note = {}
      note[:time] = n.created_at.to_i
      note[:host] = ""
      note[:service] = ""
      note[:host] = n.host.address if(n.host)
      note[:service] = n.service.name || n.service.port  if(n.service)
      note[:type ] = n.ntype.to_s
      note[:data] = n.data.inspect
      ret[:notes] << note
    end
    ret
  }
  end

  def rpc_report_auth_info(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = self.framework.db.report_auth_info(opts)
    return { :result => 'success' } if(res)
    { :result => 'failed' }
  }
  end

  def rpc_get_auth_info(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    ret = {}
    ret[:auth_info] = []
    # XXX: This method doesn't exist...
    ai = self.framework.db.get_auth_info(opts)
    ai.each do |i|
      info = {}
      i.each do |k,v|
        info[k.to_sym] = v
      end
      ret[:auth_info] << info
    end
    ret
  }
  end

  def rpc_get_ref(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    self.framework.db.get_ref(name)
  }
  end

  def rpc_del_vuln(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    hosts  = []
    services = []
    vulns = []

    if opts[:host] or opts[:address] or opts[:addresses]
      hosts = opts_to_hosts(opts)
    end

    if opts[:port] or opts[:proto]
      if opts[:host] or opts[:address] or opts[:addresses]
        services = opts_to_services(hosts,opts)
      else
        services = opts_to_services([],opts)
      end
    end

    if opts[:port] or opts[:proto]
      services.each do |s|
        vret = nil
        if opts[:name]
          vret = s.vulns.find_by_name(opts[:name])
        else
          vret = s.vulns
        end
        next if vret == nil
        vulns << vret if vret.class == ::Mdm::Vuln
        vulns |= vret if vret.class == Array
      end
    elsif opts[:address] or opts[:host] or opts[:addresses]
      hosts.each do |h|
        vret = nil
        if opts[:name]
          vret = h.vulns.find_by_name(opts[:name])
        else
          vret = h.vulns
        end
        next if vret == nil
        vulns << vret if vret.class == ::Mdm::Vuln
        vulns |= vret if vret.class == Array
      end
    else
      vret = nil
      if opts[:name]
        vret = wspace.vulns.find_by_name(opts[:name])
      else
        vret = wspace.vulns
      end
      vulns << vret if vret.class == ::Mdm::Vuln
      vulns |= vret if vret.class == Array
    end

    deleted = []
    vulns.each do |v|
      dent = {}
      dent[:address] = v.host.address.to_s if v.host
      dent[:port] = v.service.port if v.service
      dent[:proto] = v.service.proto if v.service
      dent[:name] = v.name
      deleted << dent
      v.destroy
    end

    return { :result => 'success', :deleted => deleted }
  }
  end

  def rpc_del_note(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    hosts  = []
    services = []
    notes = []

    if opts[:host] or opts[:address] or opts[:addresses]
      hosts = opts_to_hosts(opts)
    end

    if opts[:port] or opts[:proto]
      if opts[:host] or opts[:address] or opts[:addresses]
        services = opts_to_services(hosts,opts)
      else
        services = opts_to_services([],opts)
      end
    end

    if opts[:port] or opts[:proto]
      services.each do |s|
        nret = nil
        if opts[:ntype]
          nret = s.notes.find_by_ntype(opts[:ntype])
        else
          nret = s.notes
        end
        next if nret == nil
        notes << nret if nret.class == ::Mdm::Note
        notes |= nret if nret.class == Array
      end
    elsif opts[:address] or opts[:host] or opts[:addresses]
      hosts.each do |h|
        nret = nil
        if opts[:ntype]
          nret = h.notes.find_by_ntype(opts[:ntype])
        else
          nret = h.notes
        end
        next if nret == nil
        notes << nret if nret.class == ::Mdm::Note
        notes |= nret if nret.class == Array
      end
    else
      nret = nil
      if opts[:ntype]
        nret = wspace.notes.find_by_ntype(opts[:ntype])
      else
        nret = wspace.notes
      end
      notes << nret if nret.class == ::Mdm::Note
      notes |= nret if nret.class == Array
    end
    deleted = []
    notes.each do |n|
      dent = {}
      dent[:address] = n.host.address.to_s if n.host
      dent[:port] = n.service.port if n.service
      dent[:proto] = n.service.proto if n.service
      dent[:ntype] = n.ntype
      deleted << dent
      n.destroy
    end

    return { :result => 'success', :deleted => deleted }
  }
  end

  def rpc_del_service(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    hosts  = []
    services = []
    if opts[:host] or opts[:address]
      host = opts[:host] || opts[:address]
      hent = wspace.hosts.find_by_address(host)
      return { :result => 'failed' } if hent == nil or hent.class != ::Mdm::Host
      hosts << hent
    elsif opts[:addresses]
      return { :result => 'failed' } if opts[:addresses].class != Array
      conditions = { :address => opts[:addresses] }
      hent = wspace.hosts.all(:conditions => conditions)
      return { :result => 'failed' } if hent == nil
      hosts |= hent if hent.class == Array
      hosts << hent if hent.class == ::Mdm::Host
    end
    if opts[:addresses] or opts[:address] or opts[:host]
      hosts.each do |h|
        sret = nil
        if opts[:port] or opts[:proto]
          conditions = {}
          conditions[:port] = opts[:port] if opts[:port]
          conditions[:proto] = opts[:proto] if opts[:proto]
          sret = h.services.all(:conditions => conditions)
          next if sret == nil
          services << sret if sret.class == ::Mdm::Service
          services |= sret if sret.class == Array
        else
          services |= h.services
        end
      end
    elsif opts[:port] or opts[:proto]
      conditions = {}
      conditions[:port] = opts[:port] if opts[:port]
      conditions[:proto] = opts[:proto] if opts[:proto]
      sret = wspace.services.all(:conditions => conditions)
      services << sret if sret and sret.class == ::Mdm::Service
      services |= sret if sret and sret.class == Array
    end

    deleted = []
    services.each do |s|
      dent = {}
      dent[:address] = s.host.address.to_s
      dent[:port] = s.port
      dent[:proto] = s.proto
      deleted << dent
      s.destroy
    end

    return { :result => 'success', :deleted => deleted }
  }
  end

  def rpc_del_host(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    opts = fix_options(xopts)
    wspace = find_workspace(opts[:workspace])
    hosts  = []
    if opts[:host] or opts[:address]
      host = opts[:host] || opts[:address]
      hent = wspace.hosts.find_by_address(host)
      return { :result => 'failed' } if hent == nil or hent.class != ::Mdm::Host
      hosts << hent
    elsif opts[:addresses]
      return { :result => 'failed' } if opts[:addresses].class != Array
      conditions = { :address => opts[:addresses] }
      hent = wspace.hosts.all(:conditions => conditions)
      return { :result => 'failed' } if hent == nil
      hosts |= hent if hent.class == Array
      hosts << hent if hent.class == ::Mdm::Host
    end
    deleted = []
    hosts.each do |h|
      deleted << h.address.to_s
      h.destroy
    end

    return { :result => 'success', :deleted => deleted }
  }
  end

  def rpc_report_vuln(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    opts = fix_options(xopts)
    opts[:workspace] = find_workspace(opts[:workspace]) if opts[:workspace]
    res = self.framework.db.report_vuln(opts)
    return { :result => 'success' } if(res)
    { :result => 'failed' }
  }
  end

  def rpc_events(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    ret = {}
    ret[:events] = []

    wspace.events.all(:limit => limit, :offset => offset).each do |e|
      event = {}
      event[:host] = e.host.address if(e.host)
      event[:created_at] = e.created_at.to_i
      event[:updated_at] = e.updated_at.to_i
      event[:name] = e.name
      event[:critical] = e.critical if(e.critical)
      event[:username] = e.username if(e.username)
      event[:info] = e.info
      ret[:events] << event
    end
    ret
  }
  end

  def rpc_report_event(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = self.framework.db.report_event(opts)
    { :result => 'success' } if(res)
  }
  end

  #NOTE Path is required
  #NOTE To match a service need host, port, proto
  def rpc_report_loot(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    if opts[:host] && opts[:port] && opts[:proto]
      opts[:service] = self.framework.db.find_or_create_service(opts)
    end

    res = self.framework.db.report_loot(opts)
    { :result => 'success' } if(res)
  }
  end

  def rpc_loots(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    ret = {}
    ret[:loots] = []
    wspace.loots.all(:limit => limit, :offset => offset).each do |l|
      loot = {}
      loot[:host] = l.host.address if(l.host)
      loot[:service] = l.service.name || l.service.port  if(l.service)
      loot[:ltype] = l.ltype
      loot[:ctype] = l.content_type
      loot[:data] = l.data
      loot[:created_at] = l.created_at.to_i
      loot[:updated_at] = l.updated_at.to_i
      loot[:name] = l.name
      loot[:info] = l.info
      ret[:loots] << loot
    end
    ret
  }
  end

  # requires host, port, user, pass, ptype, and active
  def rpc_report_cred(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = framework.db.find_or_create_cred(opts)
    return { :result => 'success' } if res
    { :result => 'failed' }
  }
  end

  #right now workspace is the only option supported
  def rpc_creds(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    ret = {}
    ret[:creds] = []
    ::Mdm::Cred.find(:all, :include => {:service => :host}, :conditions => ["hosts.workspace_id = ?",
        framework.db.workspace.id ], :limit => limit, :offset => offset).each do |c|
      cred = {}
      cred[:host] = c.service.host.address if(c.service.host)
      cred[:updated_at] = c.updated_at.to_i
      cred[:port] = c.service.port
      cred[:proto] = c.service.proto
      cred[:sname] = c.service.name
      cred[:type] = c.ptype
      cred[:user] = c.user
      cred[:pass] = c.pass
      cred[:active] = c.active
      ret[:creds] << cred
    end
    ret
  }
  end

  def rpc_import_data(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    self.framework.db.import(opts)
    return { :result => 'success' }
  }
  end

  def rpc_get_vuln(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    ret = {}
    ret[:vuln] = []

    host = self.framework.db.get_host(opts)

    return ret if( not host)
    vulns = []

    if(opts[:proto] && opts[:port])
      services = []
      sret = host.services.find_by_proto_and_port(opts[:proto], opts[:port])
      return ret if sret == nil
      services << sret if sret.class == ::Mdm::Service
      services |= sret if sret.class == Array

      services.each do |s|
        vulns |= s.vulns
      end
    else
      vulns = host.vulns
    end

    return ret if (not vulns)

    vulns.each do |v|
      vuln= {}
      host= v.host
      vuln[:host] = host.address || "unknown"
      if v.service
        vuln[:port] = v.service.port
        vuln[:proto] = v.service.proto
      end
      vuln[:created_at] = v[:created_at].to_i
      vuln[:updated_at] = v[:updated_at].to_i
      vuln[:name] = v[:name].to_s
      vuln[:info] = v[:info].to_s
      vuln[:refs] = []
      v.refs.each do |r|
        vuln[:refs] << r.name
      end
      ret[:vuln] << vuln
    end
    ret
  }
  end

  def rpc_clients(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions[:ua_name] = opts[:ua_name] if opts[:ua_name]
    conditions[:ua_ver] = opts[:ua_ver] if opts[:ua_ver]
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]

    ret = {}
    ret[:clients] = []

    wspace.clients.all(:include => :host, :conditions => conditions,
        :limit => limit, :offset => offset).each do |c|
      client = {}
      client[:host] = c.host.address.to_s if c.host
      client[:ua_string] = c.ua_string
      client[:ua_name] = c.ua_name
      client[:ua_ver] = c.ua_ver
      client[:created_at] = c.created_at.to_i
      client[:updated_at] = c.updated_at.to_i
      ret[:clients] << client
    end
    ret
  }
  end

  def rpc_del_client(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    opts = fix_options(xopts)
    wspace = find_workspace(opts[:workspace])
    hosts = []
    clients = []

    if opts[:host] or opts[:address] or opts[:addresses]
      hosts = opts_to_hosts(opts)
    else
      hosts = wspace.hosts
    end

    hosts.each do |h|
      cret = nil
      if opts[:ua_name] or opts[:ua_ver]
        conditions = {}
        conditions[:ua_name] = opts[:ua_name] if opts[:ua_name]
        conditions[:ua_ver] = opts[:ua_ver] if opts[:ua_ver]
        cret = h.clients.all(:conditions => conditions)
      else
        cret = h.clients
      end
      next if cret == nil
      clients << cret if cret.class == ::Mdm::Client
      clients |= cret if cret.class == Array
    end

    deleted = []
    clients.each do |c|
      dent = {}
      dent[:address] = c.host.address.to_s
      dent[:ua_string] = c.ua_string
      deleted << dent
      c.destroy
    end

    { :result => 'success', :deleted => deleted }
  }
  end

  def rpc_driver(xopts)
    opts = fix_options(xopts)
    if opts[:driver]
      if self.framework.db.drivers.include?(opts[:driver])
        self.framework.db.driver = opts[:driver]
        return { :result => 'success' }
      else
        return { :result => 'failed' }

      end
    else
      return { :driver => self.framework.db.driver.to_s }
    end
    return { :result => 'failed' }
  end

  def rpc_connect(xopts)
    opts = fix_options(xopts)
    if(not self.framework.db.driver and not opts[:driver])
      return { :result => 'failed' }
    end

    if opts[:driver]
      if self.framework.db.drivers.include?(opts[:driver])
        self.framework.db.driver = opts[:driver]
      else
        return { :result => 'failed' }
      end
    end

    driver = self.framework.db.driver

    case driver
    when 'postgresql'
      opts['adapter'] = 'postgresql'
    else
      return { :result => 'failed' }
    end

    if (not self.framework.db.connect(opts))
      return { :result => 'failed' }
    end
    return { :result => 'success' }

  end

  def rpc_status
    if (not self.framework.db.driver)
      return {:driver => 'None' }
    end

    cdb = ""
    if ::ActiveRecord::Base.connected?
      ::ActiveRecord::Base.connection_pool.with_connection { |conn|
        if conn.respond_to? :current_database
          cdb = conn.current_database
        else
          cdb = conn.instance_variable_get(:@config)[:database]
        end
      }
      return {:driver => self.framework.db.driver.to_s , :db => cdb }
    else
      return {:driver => self.framework.db.driver.to_s}
    end
    {:driver => 'None' }
  end

  def rpc_disconnect
    if (self.framework.db)
      self.framework.db.disconnect()
      return { :result => 'success' }
    else
      return { :result => 'failed' }
    end
  end


end
end
end
