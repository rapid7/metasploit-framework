module Msf::DBManager::Service
  #
  # Deletes a port and associated vulns matching this port
  #
  def del_service(wspace, address, proto, port, comm='')

    host = get_host(:workspace => wspace, :address => address)
    return unless host

    with_connection {
      host.services.where({:proto => proto, :port => port}).each { |s| s.destroy }
    }
  end

  def find_or_create_service(opts)
    report_service(opts)
  end

  #
  # Record a service in the database.
  #
  # opts MUST contain
  # +:host+::  the host where this service is running
  # +:port+::  the port where this service listens
  # +:proto+:: the transport layer protocol (e.g. tcp, udp)
  #
  # opts may contain
  # +:name+::  the application layer protocol (e.g. ssh, mssql, smb)
  # +:sname+:: an alias for the above
  #
  def report_service(opts)
    with_connection {
      addr  = opts.delete(:host) || return
      hname = opts.delete(:host_name)
      hmac  = opts.delete(:mac)
      host  = nil
      wspace = opts.delete(:workspace) || workspace
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

      proto = opts[:proto] || 'tcp'

      service = host.services.find_or_initialize_by_port_and_proto(opts[:port].to_i, proto)
      opts.each { |k,v|
        if (service.attribute_names.include?(k.to_s))
          service[k] = ((v and k == :name) ? v.to_s.downcase : v)
        else
          dlog("Unknown attribute for Service: #{k}")
        end
      }
      service.state ||= ServiceState::Open
      service.info  ||= ""

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

  def get_service(wspace, host, proto, port)
    with_connection {
      host = get_host(:workspace => wspace, :address => host)
      return if not host
      return host.services.find_by_proto_and_port(proto, port)
    }
  end

  #
  # Iterates over the services table calling the supplied block with the
  # service instance of each entry.
  #
  def each_service(wspace=workspace, &block)
    with_connection {
      services(wspace).each do |service|
        block.call(service)
      end
    }
  end

  #
  # Returns a list of all services in the database
  #
  def services(wspace = workspace, only_up = false, proto = nil, addresses = nil, ports = nil, names = nil)
    with_connection {
      conditions = {}
      conditions[:state] = [ServiceState::Open] if only_up
      conditions[:proto] = proto if proto
      conditions["hosts.address"] = addresses if addresses
      conditions[:port] = ports if ports
      conditions[:name] = names if names
      wspace.services.includes(:host).where(conditions).order("hosts.address, port")
    }
  end
end