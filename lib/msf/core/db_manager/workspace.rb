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
    # Workspace tracking is handled on the client side, so attempting to call it directly from the DbManager
    # will not return the correct results. Run it back through the proxy.
    wlog "[DEPRECATION] Setting the workspace from within DbManager is no longer supported. Please call from WorkspaceDataProxy instead."
    raise NotImplementedError
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
    raise NotImplementedError
  end

  def workspace=(workspace)
    # The @current_workspace is tracked on the client side, so attempting to call it directly from the DbManager
    # will not return the correct results. Run it back through the proxy.
    wlog "[DEPRECATION] Setting the workspace from within DbManager is no longer supported. Please call from WorkspaceDataProxy instead."
    raise NotImplementedError
  end

  def workspaces(opts = {})
  ::ActiveRecord::Base.connection_pool.with_connection {
    search_term = opts.delete(:search_term)
    # Passing these values to the search will cause exceptions, so remove them if they accidentally got passed in.
    opts.delete(:workspace)
    opts.delete(:wspace)

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

  def update_workspace(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?
    wspace = opts.delete(:wspace) || opts.delete(:workspace) || workspace # TODO: Not used, but we do need to delete the key

    ::ActiveRecord::Base.connection_pool.with_connection {
      id = opts.delete(:id)
      Mdm::Workspace.update(id, opts)
    }
  end
end
