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

  #
  # This methods returns a list of all loot in the database
  #
  def loots(opts)
    wspace = opts.delete(:workspace) || opts.delete(:wspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end
    opts[:workspace_id] = wspace.id
    search_term = opts.delete(:search_term)

    ::ActiveRecord::Base.connection_pool.with_connection {
      if search_term && !search_term.empty?
        column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Loot, search_term)
        Mdm::Loot.includes(:host).where(opts).where(column_search_conditions)
      else
        Mdm::Loot.includes(:host).where(opts)
      end
    }
  end
  alias_method :loot, :loots

  def report_loot(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end
    path = opts.delete(:path) || (raise RuntimeError, "A loot :path is required")

    host = nil
    addr = nil

    # Report the host so it's there for the Proc to use below
    if opts[:host]
      if opts[:host].kind_of? ::Mdm::Host
        host = opts[:host]
      else
        host = report_host({:workspace => wspace, :host => opts[:host]})
        addr = Msf::Util::Host.normalize_host(opts[:host])
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

    loot.path         = path
    loot.ltype        = ltype
    loot.content_type = ctype
    loot.data         = data
    loot.name         = name if name
    loot.info         = info if info
    loot.workspace    = wspace
    msf_import_timestamps(opts,loot)
    loot.save!

    ret[:loot] = loot
  }
  end

  # Update the attributes of a Loot entry with the values in opts.
  # The values in opts should match the attributes to update.
  #
  # @param opts [Hash] Hash containing the updated values. Key should match the attribute to update. Must contain :id of record to update.
  # @return [Mdm::Loot] The updated Mdm::Loot object.
  def update_loot(opts)
    wspace = opts.delete(:workspace)
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
      opts[:workspace] = wspace
    end

    ::ActiveRecord::Base.connection_pool.with_connection {
      id = opts.delete(:id)
      Mdm::Loot.update(id, opts)
    }
  end

  # Deletes Loot entries based on the IDs passed in.
  #
  # @param opts[:ids] [Array] Array containing Integers corresponding to the IDs of the Loot entries to delete.
  # @return [Array] Array containing the Mdm::Loot objects that were successfully deleted.
  def delete_loot(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |loot_id|
        loot = Mdm::Loot.find(loot_id)
        begin
          deleted << loot.destroy
        rescue # refs suck
          elog("Forcibly deleting #{loot}")
          deleted << loot.delete
        end
      end

      return deleted
    }
  end
end