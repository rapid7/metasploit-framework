module WorkspaceDataProxy

  def find_workspace(workspace_name)
    begin
      data_service = self.get_data_service
      opts = { name: workspace_name }
      data_service.workspaces(opts).first
    rescue => e
      self.log_error(e, "Problem finding workspace")
    end
  end

  def add_workspace(workspace_name)
    begin
      data_service = self.get_data_service
      opts = { name: workspace_name }
      data_service.add_workspace(opts)
    rescue => e
      self.log_error(e, "Problem adding workspace")
    end
  end

  def default_workspace
    begin
      ws = find_workspace(Msf::DBManager::Workspace::DEFAULT_WORKSPACE_NAME)
      if ws.nil?
        ws = add_workspace(Msf::DBManager::Workspace::DEFAULT_WORKSPACE_NAME)
      end
      ws
    rescue => e
      self.log_error(e, "Problem finding default workspace")
    end
  end

  def workspace
    begin
      if @current_workspace
        @current_workspace
      else
        # This is mostly a failsafe to prevent bad things from happening. @current_workspace should always be set
        # outside of here, but this will save us from crashes/infinite loops if that happens
        @current_workspace = default_workspace
      end
    rescue => e
      self.log_error(e, "Problem retrieving workspace")
    end
  end

  # TODO: Tracking of the current workspace should be moved out of the datastore. See MS-3095.
  def workspace=(workspace)
    begin
      @current_workspace = workspace
    rescue => e
      self.log_error(e, "Problem setting workspace")
    end
  end

  def workspaces(opts = {})
    begin
      data_service = self.get_data_service
      data_service.workspaces(opts)
    rescue => e
      self.log_error(e, "Problem retrieving workspaces")
    end
  end

  def delete_workspaces(opts)
    begin
      data_service = self.get_data_service
      data_service.delete_workspaces(opts)
    rescue => e
      self.log_error(e, "Problem deleting workspaces")
    end
  end

  def update_workspace(opts)
    begin
      data_service = self.get_data_service
      data_service.update_workspace(opts)
    rescue => e
      self.log_error(e, "Problem updating workspace")
    end
  end
end
