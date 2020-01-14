module Msf::DBManager::Host
  # TODO: doesn't appear to have any callers. How is this used?
  # Deletes a host and associated data matching this address/comm
  def del_host(wspace, address, comm='')
  ::ActiveRecord::Base.connection_pool.with_connection {
    address, scope = address.split('%', 2)
    host = wspace.hosts.find_by_address_and_comm(address, comm)
    host.destroy if host
  }
  end

  # Deletes Host entries based on the IDs passed in.
  #
  # @param opts[:ids] [Array] Array containing Integers corresponding to the IDs of the Host entries to delete.
  # @return [Array] Array containing the Mdm::Host objects that were successfully deleted.
  def delete_host(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |host_id|
        host = Mdm::Host.find(host_id)
        begin
          deleted << host.destroy
        rescue # refs suck
          elog("Forcibly deleting #{host.address}")
          deleted << host.delete
        end
      end

      return deleted
    }
  end

  #
  # Iterates over the hosts table calling the supplied block with the host
  # instance of each entry.
  #
  def each_host(wspace=framework.db.workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.hosts.each do |host|
      block.call(host)
    end
  }
  end

  # Exactly like report_host but waits for the database to create a host and returns it.
  def find_or_create_host(opts)
    host = get_host(opts.clone)
    return host unless host.nil?

    report_host(opts)
  end

  def add_host_tag(opts)
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    ip = opts[:ip]
    tag_name = opts[:tag_name]

    host = get_host(workspace: wspace, address: ip)
    if host
      possible_tags = Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and hosts.address = ? and tags.name = ?", wspace.id, ip, tag_name).order("tags.id DESC").limit(1)
      tag = (possible_tags.blank? ? Mdm::Tag.new : possible_tags.first)
      tag.name = tag_name
      tag.hosts = [host]
      tag.save! if tag.changed?
    end
  end

  def delete_host_tag(opts)
    workspace = opts[:workspace]
    if workspace.kind_of? String
      workspace = framework.db.find_workspace(workspace)
    end

    ip = opts[:rws]
    tag_name = opts[:tag_name]

    tag_ids = []
    if ip.nil?
      found_tags = Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and tags.name = ?", workspace.id, tag_name)
      found_tags.each do |t|
        tag_ids << t.id
      end
    else
      found_tags = Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and hosts.address = ? and tags.name = ?", workspace.id, ip, tag_name)
      found_tags.each do |t|
        tag_ids << t.id
      end
    end

    tag_ids.each do |id|
      tag = Mdm::Tag.find_by_id(id)
      tag.hosts.delete
      tag.destroy
    end
  end

  #
  # Find a host.  Performs no database writes.
  #
  def get_host(opts)
    if opts.kind_of? ::Mdm::Host
      return opts
    elsif opts.kind_of? String
      raise RuntimeError, "This invocation of get_host is no longer supported: #{caller}"
    else
      address = opts[:addr] || opts[:address] || opts[:host] || return
      return address if address.kind_of? ::Mdm::Host
    end
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    address = Msf::Util::Host.normalize_host(address)
    return wspace.hosts.find_by_address(address)
  }
  end

  # Look for an address across all comms
  def has_host?(wspace,addr)
  ::ActiveRecord::Base.connection_pool.with_connection {
    address, scope = addr.split('%', 2)
    wspace.hosts.find_by_address(addr)
  }
  end

  # Returns a list of all hosts in the database
  def hosts(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      # If we have the ID, there is no point in creating a complex query.
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::Host.find(opts[:id]))
      end

      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

      conditions = {}
      conditions[:state] = [Msf::HostState::Alive, Msf::HostState::Unknown] if opts[:non_dead]
      conditions[:address] = opts[:address] if opts[:address] && !opts[:address].empty?

      if opts[:search_term] && !opts[:search_term].empty?
        column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Host, opts[:search_term])
        tag_conditions = Arel::Nodes::Regexp.new(Mdm::Tag.arel_table[:name], Arel::Nodes.build_quoted("(?mi)#{opts[:search_term]}"))
        search_conditions = column_search_conditions.or(tag_conditions)
        wspace.hosts.where(conditions).where(search_conditions).includes(:tags).references(:tags).order(:address)
      else
        wspace.hosts.where(conditions).order(:address)
      end
    }
  end

  def host_state_changed(host, ostate)
    begin
      framework.events.on_db_host_state(host, ostate)
    rescue ::Exception => e
      wlog("Exception in on_db_host_state event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end
  end

  #
  # Report a host's attributes such as operating system and service pack
  #
  # The opts parameter MUST contain
  # +:host+::         -- the host's ip address
  #
  # The opts parameter can contain:
  # +:state+::        -- one of the Msf::HostState constants
  # +:os_name+::      -- something like "Windows", "Linux", or "Mac OS X"
  # +:os_flavor+::    -- something like "Enterprise", "Pro", or "Home"
  # +:os_sp+::        -- something like "SP2"
  # +:os_lang+::      -- something like "English", "French", or "en-US"
  # +:arch+::         -- one of the ARCHITECTURES listed in metasploit_data_models/app/models/mdm/host.rb
  # +:mac+::          -- the host's MAC address
  # +:scope+::        -- interface identifier for link-local IPv6
  # +:virtual_host+:: -- the name of the virtualization software, eg "VMWare", "QEMU", "Xen", "Docker", etc.
  #
  def report_host(opts)

    return if !active
    addr = opts.delete(:host) || return

    # Sometimes a host setup through a pivot will see the address as "Remote Pipe"
    if addr.eql? "Remote Pipe"
      return
    end

  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    opts = opts.clone
    opts.delete(:workspace)

    begin
      retry_attempts ||= 0
      if !addr.kind_of? ::Mdm::Host
        addr = Msf::Util::Host.normalize_host(addr)

        unless ipv46_validator(addr)
          raise ::ArgumentError, "Invalid IP address in report_host(): #{addr}"
        end

        conditions = {address: addr}
        conditions[:comm] = opts[:comm] if !opts[:comm].nil? && opts[:comm].length > 0
        host = wspace.hosts.where(conditions).first_or_initialize
      else
        host = addr
      end

      ostate = host.state

      # Truncate the info field at the maximum field length
      if opts[:info]
        opts[:info] = opts[:info][0,65535]
      end

      # Truncate the name field at the maximum field length
      if opts[:name]
        opts[:name] = opts[:name][0,255]
      end

      if opts[:os_name]
        os_name, os_flavor = split_windows_os_name(opts[:os_name])
        opts[:os_name] = os_name if os_name.present?
        if opts[:os_flavor].present?
          if os_flavor.present? # only prepend if there is a value that needs it
            opts[:os_flavor] = os_flavor + opts[:os_flavor]
          end
        else
          opts[:os_flavor] = os_flavor
        end
      end

      opts.each do |k,v|
        if host.attribute_names.include?(k.to_s)
          unless host.attribute_locked?(k.to_s)
            host[k] = v.to_s.gsub(/[\x00-\x1f]/n, '')
          end
        elsif !v.blank?
          dlog("Unknown attribute for ::Mdm::Host: #{k}")
        end
      end
      host.info = host.info[0,::Mdm::Host.columns_hash["info"].limit] if host.info

      # Set default fields if needed
      host.state = Msf::HostState::Alive if host.state.nil? || host.state.empty?
      host.comm = '' unless host.comm
      host.workspace = wspace unless host.workspace

      begin
        framework.events.on_db_host(host) if host.new_record?
      rescue => e
        wlog("Exception in on_db_host event handler: #{e.class}: #{e}")
        wlog("Call Stack\n#{e.backtrace.join("\n")}")
      end

      host_state_changed(host, ostate) if host.state != ostate

      if host.changed?
        msf_import_timestamps(opts, host)
        host.save!
      end
    rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
      # two concurrent report requests for a new host could result in a RecordNotUnique or
      # RecordInvalid exception, simply retry the report once more as an optimistic approach
      retry if (retry_attempts+=1) <= 1
      raise
    end

    if opts[:task]
      Mdm::TaskHost.create(
          :task => opts[:task],
          :host => host
      )
    end

    host
  }
  end

  def update_host(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      # process workspace string for update if included in opts
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts = opts.clone()
      opts[:workspace] = wspace if wspace

      id = opts.delete(:id)
      host = Mdm::Host.find(id)
      host.update!(opts)
      return host
    }
  end

  def split_windows_os_name(os_name)
    return [] if os_name.nil?
    flavor_match = os_name.match(/Windows\s+(.*)/)
    return [] if flavor_match.nil?
    ["Windows", flavor_match.captures.first]
  end
end
