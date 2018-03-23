module Msf::DBManager::Workspace
  #
  # Creates a new workspace in the database
  #
  def add_workspace(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.where(name: name).first_or_create
  }
  end

  def default_workspace
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.default
  }
  end

  def find_workspace(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.find_by_name(name)
  }
  end

  def workspace
    framework.db.find_workspace(@workspace_name)
  end

  def workspace=(workspace)
    @workspace_name = workspace.name
  end

  def workspaces
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.order('updated_at asc').load
  }
  end

  #
  # Returns an array of all the associated workspace records counts.
  #
  def workspace_associations_counts()
    results = Array.new()

    ::ActiveRecord::Base.connection_pool.with_connection {
      workspaces.each do |ws|
        results << {
            :name  => ws.name,
            :hosts_count => ws.hosts.count,
            :services_count => ws.services.count,
            :vulns_count => ws.vulns.count,
            :creds_count => ws.core_credentials.count,
            :loots_count => ws.loots.count,
            :notes_count => ws.notes.count
        }
      end
    }

    return results
  end

  def delete_all_workspaces()
    return delete_workspaces(workspaces.map(&:name))
  end

  def delete_workspaces(names)
    status_msg = []
    error_msg = []

    switched = false
    # Delete workspaces
    names.each do |name|
      workspace = framework.db.find_workspace(name)
      if workspace.nil?
        error << "Workspace not found: #{name}"
      elsif workspace.default?
        workspace.destroy
        workspace = framework.db.add_workspace(name)
        status_msg << 'Deleted and recreated the default workspace'
      else
        # switch to the default workspace if we're about to delete the current one
        if framework.db.workspace.name == workspace.name
          framework.db.workspace = framework.db.default_workspace
          switched = true
        end
        # now destroy the named workspace
        workspace.destroy
        status_msg << "Deleted workspace: #{name}"
      end
    end
    (status_msg << "Switched workspace: #{framework.db.workspace.name}") if switched
    return status_msg, error_msg
  end

  #
  # Renames a workspace
  #
  def rename_workspace(from_name, to_name)
    raise "Workspace exists: #{to_name}" if framework.db.find_workspace(to_name)

    workspace = find_workspace(from_name)
    raise "Workspace not found: #{name}" if workspace.nil?

    workspace.name = new
    workspace.save!

    # Recreate the default workspace to avoid errors
    if workspace.default?
      framework.db.add_workspace(from_name)
      #print_status("Recreated default workspace after rename")
    end

    # Switch to new workspace if old name was active
    if (@workspace_name == workspace.name)
      framework.db.workspace = workspace
      #print_status("Switched workspace: #{framework.db.workspace.name}")
    end
  end

  def get_workspace(opts)
    workspace = opts.delete(:wspace) || opts.delete(:workspace) || workspace
    find_workspace(workspace) if (workspace.is_a?(String))
  end
end
