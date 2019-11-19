module Msf::DBManager::Workspace

  DEFAULT_WORKSPACE_NAME = 'default'
  #
  # Creates a new workspace in the database
  #
  def add_workspace(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.where(name: opts[:name]).first_or_create
  }
  end

  def default_workspace
    # Workspace tracking is handled on the client side, so attempting to call it directly from the DbManager
    # will not return the correct results. Run it back through the proxy.


    wlog "[DEPRECATION] Setting the workspace from within DbManager is no longer supported. Please call from WorkspaceDataProxy instead."

    # Proxied to fix tests, will be cleaned up in remote test patch
    framework.db.default_workspace
  end

  def find_workspace(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.find_by_name(name)
  }
  end

  def workspace
    # The @current_workspace is tracked on the client side, so attempting to call it directly from the DbManager
    # will not return the correct results. Run it back through the proxy.
    wlog "[DEPRECATION] Calling workspace from within DbManager is no longer supported. Please call from WorkspaceDataProxy instead."

    # Proxied to fix tests, will be cleaned up in remote test patch
    framework.db.workspace
  end

  def workspace=(workspace)
    # The @current_workspace is tracked on the client side, so attempting to call it directly from the DbManager
    # will not return the correct results. Run it back through the proxy.
    wlog "[DEPRECATION] Setting the workspace from within DbManager is no longer supported. Please call from WorkspaceDataProxy instead."

    # Proxied to fix tests, will be cleaned up in remote test patch
    framework.db.workspace=workspace
  end

  def workspaces(opts = {})
  ::ActiveRecord::Base.connection_pool.with_connection {
    # If we have the ID, there is no point in creating a complex query.
    if opts[:id] && !opts[:id].to_s.empty?
      return Array.wrap(Mdm::Workspace.find(opts[:id]))
    end

    search_term = opts.delete(:search_term)
    # Passing these values to the search will cause exceptions, so remove them if they accidentally got passed in.
    Msf::Util::DBManager.delete_opts_workspace(opts)

    ::ActiveRecord::Base.connection_pool.with_connection {
      if search_term && !search_term.empty?
        column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Workspace, search_term)
        Mdm::Workspace.where(opts).where(column_search_conditions)
      else
        Mdm::Workspace.where(opts)
      end
    }
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
        begin
          deleted << ws.destroy
          if default_deleted
            add_workspace({ name: DEFAULT_WORKSPACE_NAME })
            default_deleted = false
          end
        rescue
          elog("Forcibly deleting #{ws.name}")
          deleted << ws.delete
        end
      end

      return deleted
    }
  end

  def update_workspace(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?
    Msf::Util::DBManager.delete_opts_workspace(opts)

    ::ActiveRecord::Base.connection_pool.with_connection {
      ws_id = opts.delete(:id)
      ws_to_update = workspaces({ id: ws_id }).first
      default_renamed = true if ws_to_update.name == DEFAULT_WORKSPACE_NAME
      begin
        ws_to_update.update!(opts) # will raise exception if it fails
      rescue ActiveRecord::RecordInvalid => e
        raise ArgumentError.new(e.message)
      end
      add_workspace({ name: DEFAULT_WORKSPACE_NAME }) if default_renamed
      workspaces({ id: ws_id }).first
    }
  end
end
