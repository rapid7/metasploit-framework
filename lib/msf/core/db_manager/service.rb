module Msf::DBManager::Service
  # Deletes a port and associated vulns matching this port
  def delete_service(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

  ::ActiveRecord::Base.connection_pool.with_connection {
    deleted = []
    opts[:ids].each do |service_id|
      service = Mdm::Service.find(service_id)
      begin
        deleted << service.destroy
      rescue
        elog("Forcibly deleting #{service.name}")
        deleted << service.delete
      end
    end

    return deleted
  }
  end

  # Iterates over the services table calling the supplied block with the
  # service instance of each entry.
  def each_service(wspace=framework.db.workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.services.each do |service|
      block.call(service)
    end
  }
  end

  def find_or_create_service(opts)
    report_service(opts)
  end

  def get_service(wspace, host, proto, port)
  ::ActiveRecord::Base.connection_pool.with_connection {
    host = get_host(:workspace => wspace, :address => host)
    return if !host
    return host.services.find_by_proto_and_port(proto, port)
  }
  end

  #
  # Record a service in the database.
  #
  # opts MUST contain
  # +:host+::  the host where this service is running
  # +:port+::  the port where this service listens
  # +:proto+:: the transport layer protocol (e.g. tcp, udp)
  # +:workspace+:: the workspace for the service
  #
  # opts may contain
  # +:name+::  the application layer protocol (e.g. ssh, mssql, smb)
  # +:sname+:: an alias for the above
  # +:info+:: Detailed information about the service such as name and version information
  # +:state+:: The current listening state of the service (one of: open, closed, filtered, unknown)
  #
  def report_service(opts)
    return if !active
  ::ActiveRecord::Base.connection_pool.with_connection { |conn|
    addr  = opts.delete(:host) || return
    hname = opts.delete(:host_name)
    hmac  = opts.delete(:mac)
    host  = nil
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    hopts = {:workspace => wspace, :host => addr}
    hopts[:name] = hname if hname
    hopts[:mac]  = hmac  if hmac

    # Other report_* methods take :sname to mean the service name, so we
    # map it here to ensure it ends up in the right place despite not being
    # a real column.
    if opts[:sname]
      opts[:name] = opts.delete(:sname)
    end

    if addr.kind_of? ::Mdm::Host
      host = addr
      addr = host.address
    else
      host = report_host(hopts)
    end

    if opts[:port].to_i.zero?
      dlog("Skipping port zero for service '%s' on host '%s'" % [opts[:name],host.address])
      return nil
    end

    ret  = {}
=begin
    host = get_host(:workspace => wspace, :address => addr)
    if host
      host.updated_at = host.created_at
      host.state      = HostState::Alive
      host.save!
    end
=end

    proto = opts[:proto] || Msf::DBManager::DEFAULT_SERVICE_PROTO

    service = host.services.where(port: opts[:port].to_i, proto: proto).first_or_initialize
    ostate = service.state
    opts.each { |k,v|
      if (service.attribute_names.include?(k.to_s))
        service[k] = ((v and k == :name) ? v.to_s.downcase : v)
      elsif !v.blank?
        dlog("Unknown attribute for Service: #{k}")
      end
    }
    service.state ||= Msf::ServiceState::Open
    service.info  ||= ""

    begin
      framework.events.on_db_service(service) if service.new_record?
    rescue ::Exception => e
      wlog("Exception in on_db_service event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end

    begin
      framework.events.on_db_service_state(service, service.port, ostate) if service.state != ostate
    rescue ::Exception => e
      wlog("Exception in on_db_service_state event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end

    if (service and service.changed?)
      msf_import_timestamps(opts,service)
      service.save!
    end

    if opts[:task]
      Mdm::TaskService.create(
          :task => opts[:task],
          :service => service
      )
    end

    ret[:service] = service
  }
  end

  # Returns a list of all services in the database
  def services(opts)
    search_term = opts.delete(:search_term)

    order_args = [:port]
    order_args.unshift(Mdm::Host.arel_table[:address]) if opts.key?(:hosts)

  ::ActiveRecord::Base.connection_pool.with_connection {
    # If we have the ID, there is no point in creating a complex query.
    if opts[:id] && !opts[:id].to_s.empty?
      return Array.wrap(Mdm::Service.find(opts[:id]))
    end

    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    if search_term && !search_term.empty?
      column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Service, search_term)
      wspace.services.includes(:host).where(opts).where(column_search_conditions).order(*order_args)
    else
      wspace.services.includes(:host).where(opts).order(*order_args)
    end
  }
  end

  def update_service(opts)
    opts.delete(:workspace) # Workspace isn't used with Mdm::Service. So strip it if it's present.

  ::ActiveRecord::Base.connection_pool.with_connection {
    id = opts.delete(:id)
    service = Mdm::Service.find(id)
    service.update!(opts)
    return service
  }
  end
end
