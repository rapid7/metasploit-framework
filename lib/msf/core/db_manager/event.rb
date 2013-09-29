module Msf::DBManager::Event
  def events(wspace=workspace)
    with_connection {
      wspace.events.find :all, :order => 'created_at ASC'
    }
  end

  def report_event(opts = {})
    with_connection {
      wspace = opts.delete(:workspace) || workspace
      return if not wspace # Temp fix?
      uname  = opts.delete(:username)

      if ! opts[:host].kind_of? ::Mdm::Host and opts[:host]
        opts[:host] = report_host(:workspace => wspace, :host => opts[:host])
      end

      Mdm::Event.create(opts.merge(:workspace_id => wspace[:id], :username => uname))
    }
  end
end