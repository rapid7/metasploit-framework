module Msf::DBManager::Loot
  #
  # Loot collection
  #
  #
  # This method iterates the loot table calling the supplied block with the
  # instance of each entry.
  #
  def each_loot(wspace=workspace, &block)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace.loots.each do |note|
        block.call(note)
      end
    }
  end

  #
  # Find or create a loot matching this type/data
  #
  def find_or_create_loot(opts)
    report_loot(opts)
  end

  def report_loot(opts)
    return if not active
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace = opts.delete(:workspace) || workspace
      path = opts.delete(:path) || (raise RuntimeError, "A loot :path is required")

      host = nil
      addr = nil

      # Report the host so it's there for the Proc to use below
      if opts[:host]
        if opts[:host].kind_of? ::Mdm::Host
          host = opts[:host]
        else
          host = report_host({:workspace => wspace, :host => opts[:host]})
          addr = normalize_host(opts[:host])
        end
      end

      ret = {}

      ltype  = opts.delete(:type) || opts.delete(:ltype) || (raise RuntimeError, "A loot :type or :ltype is required")
      ctype  = opts.delete(:ctype) || opts.delete(:content_type) || 'text/plain'
      name   = opts.delete(:name)
      info   = opts.delete(:info)
      data   = opts[:data]
      loot   = wspace.loots.new

      if host
        loot.host_id = host[:id]
      end
      if opts[:service] and opts[:service].kind_of? ::Mdm::Service
        loot.service_id = opts[:service][:id]
      end

      loot.path  = path
      loot.ltype = ltype
      loot.content_type = ctype
      loot.data  = data
      loot.name  = name if name
      loot.info  = info if info
      msf_import_timestamps(opts,loot)
      loot.save!

      if !opts[:created_at]
=begin
      if host
        host.updated_at = host.created_at
        host.state      = HostState::Alive
        host.save!
      end
=end
      end

      ret[:loot] = loot
    }
  end

  #
  # This methods returns a list of all loot in the database
  #
  def loots(wspace=workspace)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace.loots
    }
  end
end