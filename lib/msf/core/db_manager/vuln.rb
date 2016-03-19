module Msf::DBManager::Vuln
  #
  # This method iterates the vulns table calling the supplied block with the
  # vuln instance of each entry.
  #
  def each_vuln(wspace=workspace,&block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.vulns.each do |vulns|
      block.call(vulns)
    end
  }
  end

  #
  # Find or create a vuln matching this service/name
  #
  def find_or_create_vuln(opts)
    report_vuln(opts)
  end

  def find_vuln_by_details(details_map, host, service=nil)

    # Create a modified version of the criteria in order to match against
    # the joined version of the fields

    crit = {}
    details_map.each_pair do |k,v|
      crit[ "vuln_details.#{k}" ] = v
    end

    vuln = nil

    if service
      vuln = service.vulns.includes(:vuln_details).where(crit).first
    end

    # Return if we matched based on service
    return vuln if vuln

    # Prevent matches against other services
    crit["vulns.service_id"] = nil if service
    vuln = host.vulns.includes(:vuln_details).where(crit).first

    return vuln
  end

  def find_vuln_by_refs(refs, host, service=nil)
    ref_ids = refs.find_all { |ref| ref.name.starts_with? 'CVE-'}
    relation = host.vulns.includes(:refs)
    if !service.try(:id).nil?
      return relation.where(service_id: service.try(:id), refs: { id: ref_ids}).first
    end
    return relation.where(refs: { id: ref_ids}).first
  end

  def get_vuln(wspace, host, service, name, data='')
    raise RuntimeError, "Not workspace safe: #{caller.inspect}"
  ::ActiveRecord::Base.connection_pool.with_connection {
    vuln = nil
    if (service)
      vuln = ::Mdm::Vuln.find.where("name = ? and service_id = ? and host_id = ?", name, service.id, host.id).order("vulns.id DESC").first()
    else
      vuln = ::Mdm::Vuln.find.where("name = ? and host_id = ?", name, host.id).first()
    end

    return vuln
  }
  end

  #
  # Find a vulnerability matching this name
  #
  def has_vuln?(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    Mdm::Vuln.find_by_name(name)
  }
  end

  #
  # opts MUST contain
  # +:host+:: the host where this vulnerability resides
  # +:name+:: the friendly name for this vulnerability (title)
  #
  # opts can contain
  # +:info+::   a human readable description of the vuln, free-form text
  # +:refs+::   an array of Ref objects or string names of references
  # +:details:: a hash with :key pointed to a find criteria hash and the rest containing VulnDetail fields
  #
  def report_vuln(opts)
    return if not active
    raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
    raise ArgumentError.new("Deprecated data column for vuln, use .info instead") if opts[:data]
    name = opts[:name] || return
    info = opts[:info]

  ::ActiveRecord::Base.connection_pool.with_connection {

    wspace = opts.delete(:workspace) || workspace
    exploited_at = opts[:exploited_at] || opts["exploited_at"]
    details = opts.delete(:details)
    rids = opts.delete(:ref_ids)

    if opts[:refs]
      rids ||= []
      opts[:refs].each do |r|
        if (r.respond_to?(:ctx_id)) and (r.respond_to?(:ctx_val))
          r = "#{r.ctx_id}-#{r.ctx_val}"
        end
        rids << find_or_create_ref(:name => r)
      end
    end

    host = nil
    addr = nil
    if opts[:host].kind_of? ::Mdm::Host
      host = opts[:host]
    else
      host = report_host({:workspace => wspace, :host => opts[:host]})
      addr = normalize_host(opts[:host])
    end

    ret = {}

    # Truncate the info field at the maximum field length
    if info
      info = info[0,65535]
    end

    # Truncate the name field at the maximum field length
    name = name[0,255]

    # Placeholder for the vuln object
    vuln = nil

    # Identify the associated service
    service = opts.delete(:service)

    # Treat port zero as no service
    if service or opts[:port].to_i > 0

      if not service
        proto = nil
        case opts[:proto].to_s.downcase # Catch incorrect usages, as in report_note
        when 'tcp','udp'
          proto = opts[:proto]
        when 'dns','snmp','dhcp'
          proto = 'udp'
          sname = opts[:proto]
        else
          proto = 'tcp'
          sname = opts[:proto]
        end

        service = host.services.where(port: opts[:port].to_i, proto: proto).first_or_create
      end

      # Try to find an existing vulnerability with the same service & references
      # If there are multiple matches, choose the one with the most matches
      # If a match is found on a vulnerability with no associated service,
      # update that vulnerability with our service information. This helps
      # prevent dupes of the same vuln found by both local patch and
      # service detection.
      if rids and rids.length > 0
        vuln = find_vuln_by_refs(rids, host, service)
        vuln.service = service if vuln
      end
    else
      # Try to find an existing vulnerability with the same host & references
      # If there are multiple matches, choose the one with the most matches
      if rids and rids.length > 0
        vuln = find_vuln_by_refs(rids, host)
      end
    end

    # Try to match based on vuln_details records
    if not vuln and opts[:details_match]
      vuln = find_vuln_by_details(opts[:details_match], host, service)
      if vuln and service and not vuln.service
        vuln.service = service
      end
    end

    # No matches, so create a new vuln record
    unless vuln
      if service
        vuln = service.vulns.find_by_name(name)
      else
        vuln = host.vulns.find_by_name(name)
      end

      unless vuln

        vinf = {
          :host_id => host.id,
          :name    => name,
          :info    => info
        }

        vinf[:service_id] = service.id if service
        vuln = Mdm::Vuln.create(vinf)
      end
    end

    # Set the exploited_at value if provided
    vuln.exploited_at = exploited_at if exploited_at

    # Merge the references
    if rids
      vuln.refs << (rids - vuln.refs)
    end

    # Finalize
    if vuln.changed?
      msf_import_timestamps(opts,vuln)
      vuln.save!
    end

    # Handle vuln_details parameters
    report_vuln_details(vuln, details) if details

    vuln
  }
  end

  #
  # This methods returns a list of all vulnerabilities in the database
  #
  def vulns(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.vulns
  }
  end
end
