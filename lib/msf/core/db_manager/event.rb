module Msf::DBManager::Event
  def events(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    # If we have the ID, there is no point in creating a complex query.
    if opts[:id] && !opts[:id].to_s.empty?
      return Array.wrap(Mdm::Event.find(opts[:id]))
    end

    wspace.events.find :all, :order => 'created_at ASC'
  }
  end

  def report_event(opts = {})
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    return if not wspace # Temp fix?
    uname  = opts.delete(:username)

    if !opts[:host].nil? && !opts[:host].kind_of?(::Mdm::Host)
      opts[:host] = find_or_create_host(workspace: wspace, host: opts[:host])
    end

    ::Mdm::Event.create(opts.merge(:workspace_id => wspace[:id], :username => uname))
  }
  end
end