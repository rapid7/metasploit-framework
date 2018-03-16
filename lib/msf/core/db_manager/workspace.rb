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

  def delete_workspaces(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {
      deleted = []
      default_deleted = false
      opts[:ids].each do |ws_id|
        ws = Mdm::Workspace.find(ws_id)
        default_deleted = true if ws.default?
        if framework.db.workspace.name == ws.name
          framework.db.workspace = framework.db.default_workspace
        end
        begin
          deleted << ws.destroy
          framework.db.workspace = framework.db.add_workspace('default') if default_deleted
        rescue
          elog("Forcibly deleting #{workspace}")
          deleted << ws.delete
        end
      end

      return deleted
    }
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
