module WorkspaceDataProxy

  def find_workspace(workspace_name)
    begin
      data_service = self.get_data_service
      opts = { :name => workspace_name }
      data_service.workspaces(opts).first
    rescue  Exception => e
      self.log_error(e, "Problem finding workspace")
    end
  end

  def add_workspace(workspace_name)
    begin
      data_service = self.get_data_service
      data_service.add_workspace(workspace_name)
    rescue  Exception => e
      self.log_error(e, "Problem adding workspace")
    end
  end

  def default_workspace
    begin
      find_workspace('default')
    rescue  Exception => e
      self.log_error(e, "Problem finding default workspace")
    end
  end

  def workspace
    begin
      if @current_workspace_id
        workspaces({ :id => @current_workspace_id }).first
      else
        default_workspace
      end
    rescue  Exception => e
      self.log_error(e, "Problem retrieving workspace")
    end
  end

  # TODO: Tracking of the current workspace should be moved out of the datastore.
  # See MS-3095
  def workspace=(workspace)
    begin
      @current_workspace_id = workspace.id
    rescue  Exception => e
      self.log_error(e, "Problem setting workspace")
    end
  end

  def workspaces(opts = {})
    begin
      data_service = self.get_data_service
      data_service.workspaces(opts)
    rescue  Exception => e
      self.log_error(e, "Problem retrieving workspaces")
    end
  end

  def delete_workspaces(workspace_ids)
    begin
      data_service = self.get_data_service
      opts = {}
      opts[:ids] = workspace_ids
      data_service.delete_workspaces(opts)
    rescue Exception => e
      self.log_error(e, "Problem deleting workspaces")
    end
  end

  def update_workspace(opts)
    begin
      data_service = self.get_data_service
      data_service.update_workspace(opts)
    rescue Exception => e
      self.log_error(e, "Problem updating workspace")
    end
  end
end
