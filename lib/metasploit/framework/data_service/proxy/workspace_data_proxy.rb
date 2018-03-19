module WorkspaceDataProxy

  def find_workspace(workspace_name)
    begin
      data_service = self.get_data_service
      data_service.find_workspace(workspace_name)
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
      data_service = self.get_data_service
      data_service.default_workspace
    rescue  Exception => e
      self.log_error(e, "Problem finding default workspace")
    end
  end

  def workspace
    begin
      data_service = self.get_data_service
      data_service.workspace
    rescue  Exception => e
      self.log_error(e, "Problem retrieving workspace")
    end
  end

  def workspace=(workspace)
    begin
      data_service = self.get_data_service
      data_service.workspace = workspace
    rescue  Exception => e
      self.log_error(e, "Problem setting workspace")
    end
  end

  def workspaces
    begin
      data_service = self.get_data_service
      data_service.workspaces
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
