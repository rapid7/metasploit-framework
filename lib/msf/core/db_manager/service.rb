module Msf::DBManager::Service
  # Deletes a port and associated vulns matching this port
  def delete_service(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

  ::ApplicationRecord.connection_pool.with_connection {
    deleted = []
    opts[:ids].each do |service_id|
      begin
        service = Mdm::Service.find(service_id)
      rescue ActiveRecord::RecordNotFound
        # This happens when the service was the child of another service we have already deleted
        # Deletion of children is automatic via dependent: :destroy on the association
        dlog("Service with id #{service_id} already deleted")
        next
      end
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
  ::ApplicationRecord.connection_pool.with_connection {
    wspace.services.each do |service|
      block.call(service)
    end
  }
  end

  def find_or_create_service(opts)
    report_service(opts)
  end

  # Maps well-known protocol symbols to their parent chain.
  # Each entry lists the immediate parent(s) that should be auto-created.
  # The chain is resolved recursively, e.g. :https → :ssl → :tcp.
  SERVICE_PARENT_MAP = {
    tcp:   [],
    ssl:   [:tcp],
    http:  [:tcp],
    https: [:ssl]
  }.freeze

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
  # +:name+::     the application layer protocol (e.g. ssh, mssql, smb)
  # +:sname+::    an alias for the above
  # +:info+::     detailed information about the service such as name and version information
  # +:state+::    the current listening state of the service (one of: open, closed, filtered, unknown)
  # +:resource+:: the resource this service is associated with, such as a a DN for an an LDAP object
  #               base URI for a web application, pipe name for DCERPC service, etc.
  # +:parents+::  a single service Hash or an Array of service Hash representing the parent services this
  #               service is associated with, such as a HTTP service for a web application.
  #               This can also be an array of symbols, with one or more values from :http, :https, :ssl, :tcp
  #               This helps avoid the need to explicitly create Mdm::Service objects, and lets this method take care of that
  #               The symbol and Mdm::Service objects cannot be mix-and-matched.
  #`
  # @return [Mdm::Service,nil]
  def report_service(opts)
    return if !active

  ::ApplicationRecord.connection_pool.with_connection do |conn|
    opts = opts.clone() # protect the original caller's opts
    addr  = opts.delete(:host) || return
    hname = opts.delete(:host_name)
    hmac  = opts.delete(:mac)
    host  = nil
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    opts.delete(:workspace) # this may not be needed however the service creation below might complain if missing
    hopts = {:workspace => wspace, :host => addr}
    hopts[:name] = hname if hname
    hopts[:mac]  = hmac  if hmac

    # Other report_* methods take :sname to mean the service name, so we
    # map it here to ensure it ends up in the right place despite not being
    # a real column.
    if opts[:sname]
      opts[:name] = opts.delete(:sname)
    end
    opts[:name] = opts[:name].to_s.downcase if opts[:name]

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

    proto = opts[:proto] || Msf::DBManager::DEFAULT_SERVICE_PROTO

    sopts = {
      port: opts[:port].to_i,
      proto: proto
    }
    sopts[:name] = opts[:name] if opts[:name]
    sopts[:resource] = opts[:resource] if opts[:resource]
    service = host.services.where(sopts).first_or_initialize

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

    # Determine parent services:
    # 1. If explicit parents are provided, use those
    # 2. If the service name is a known protocol (http, https, ssl), auto-create the parent chain
    # 3. If the service proto is 'tcp' and no parents are otherwise determined, auto-create a TCP parent
    # 4. Otherwise, no parents (current behaviour)
    explicit_parents = opts.delete(:parents)
    parent_refs = if explicit_parents
                    explicit_parents
                  elsif opts[:name] && SERVICE_PARENT_MAP.key?(opts[:name].to_sym)
                    SERVICE_PARENT_MAP[opts[:name].to_sym]
                  elsif proto == 'tcp'
                    [:tcp]
                  end

    if parent_refs&.any?
      parents = process_service_chain(host, parent_refs, port: opts[:port].to_i, proto: proto)
      if parents
        parents.each do |parent|
          service.parents << parent if parent && !service.parents.include?(parent)
        end
      end
    end

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
      service.save!
    end

    if opts[:task]
      Mdm::TaskService.where(
          :task => opts[:task],
          :service => service
      ).first_or_create
    end

    service
  end
  end

  # Returns a list of all services in the database
  def services(opts)
    opts = opts.clone()
    search_term = opts.delete(:search_term)

    order_args = [:port]
    order_args.unshift(Mdm::Host.arel_table[:address]) if opts.key?(:hosts)

  ::ApplicationRecord.connection_pool.with_connection {
    # If we have the ID, there is no point in creating a complex query.
    if opts[:id] && !opts[:id].to_s.empty?
      return Array.wrap(Mdm::Service.find(opts[:id]))
    end

    opts = opts.clone() # protect the original caller's opts
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    opts.delete(:workspace)

    if search_term && !search_term.empty?
      column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Service, search_term)
      wspace.services.includes(:host).where(opts).where(column_search_conditions).order(*order_args)
    else
      wspace.services.includes(:host).where(opts).order(*order_args)
    end
  }
  end

  def update_service(opts)
    opts = opts.clone() # it is not polite to change arguments passed from callers
    opts.delete(:workspace) # Workspace isn't used with Mdm::Service. So strip it if it's present.

  ::ApplicationRecord.connection_pool.with_connection {
    id = opts.delete(:id)
    service = Mdm::Service.find(id)
    service.update!(opts)
    return service
  }
  end

  # Resolves an array of parent service references into Mdm::Service objects.
  #
  # Each element can be:
  # - A Symbol (:tcp, :ssl, :http, :https) — auto-created using SERVICE_PARENT_MAP
  # - An Mdm::Service object — used directly
  # - A Hash with service attributes — found or created
  #
  # @param host [Mdm::Host] the host to associate services with
  # @param services [Array, Hash, Symbol, Mdm::Service, nil] parent service reference(s)
  # @param port [Integer] the port to use when resolving symbol parents (inherited from the child)
  # @param proto [String] the protocol to use when resolving symbol parents
  # @return [Array<Mdm::Service>, nil] resolved parent service objects
  def process_service_chain(host, services, port: nil, proto: 'tcp')
    return unless host.is_a?(Mdm::Host)

    return if services.nil?

    services = [services] unless services.is_a?(Array)
    services.map do |service|
      case service
      when ::Symbol
        resolve_symbol_service(host, service, port: port, proto: proto)
      when ::Mdm::Service
        service
      when ::Hash
        next if service[:port].nil? || service[:proto].nil?

        parents = nil
        if service[:parents]&.any?
          parents = process_service_chain(host, service[:parents], port: service[:port].to_i, proto: service[:proto].to_s.downcase)
        end

        service_info = {
          port: service[:port].to_i,
          proto: service[:proto].to_s.downcase
        }
        service_info[:name] = service[:name].downcase if service[:name]
        service_info[:resource] = service[:resource] if service[:resource]
        service_obj = host.services.find_or_create_by(service_info)
        if service_obj.id.nil?
          elog("Failed to create service #{service_info.inspect} for host #{host.name} (#{host.address})")
          next
        end
        service_obj.state ||= Msf::ServiceState::Open
        service_obj.info = service[:info] || ''

        if parents
          parents.each do |parent|
            service_obj.parents << parent if parent && !service_obj.parents.include?(parent)
          end
        end

        service_obj.save! if service_obj.changed?
        service_obj
      else
        next
      end
    end.compact
  end

  private

  # Resolves a symbol (e.g. :https, :http, :ssl, :tcp) into an Mdm::Service record,
  # recursively creating any parent services defined in SERVICE_PARENT_MAP.
  #
  # @param host [Mdm::Host] the host to associate the service with
  # @param sym [Symbol] the service symbol to resolve
  # @param port [Integer] the port number (inherited from the child service)
  # @param proto [String] the transport protocol
  # @return [Mdm::Service] the resolved or created service record
  def resolve_symbol_service(host, sym, port:, proto: 'tcp')
    unless SERVICE_PARENT_MAP.key?(sym)
      elog("Unknown service symbol '#{sym}' passed to resolve_symbol_service")
      return nil
    end

    # Recursively resolve this symbol's own parents first
    parent_syms = SERVICE_PARENT_MAP[sym]
    parents = if parent_syms.any?
                process_service_chain(host, parent_syms, port: port, proto: proto)
              end

    service_info = {
      port: port,
      proto: proto,
      name: sym.to_s
    }
    service_obj = host.services.where(service_info).first_or_create!(state: Msf::ServiceState::Open)

    if parents&.any?
      parents.each do |parent|
        service_obj.parents << parent if parent && !service_obj.parents.include?(parent)
      end
    end

    service_obj
  end
end
