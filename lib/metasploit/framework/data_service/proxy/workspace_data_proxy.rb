module WorkspaceDataProxy

  def find_workspace(workspace_name)
    begin
      data_service = self.get_data_service()
      data_service.find_workspace(workspace_name)
    rescue  Exception => e
      self.log_error(e, "Problem finding workspace")
    end
  end

  def add_workspace(workspace_name)
    begin
      data_service = self.get_data_service()
      data_service.add_workspace(workspace_name)
    rescue  Exception => e
      self.log_error(e, "Problem adding workspace")
    end
  end

  def default_workspace
    begin
      data_service = self.get_data_service()
      data_service.default_workspace
    rescue  Exception => e
      self.log_error(e, "Problem finding default workspace")
    end
  end

  def workspace
    begin
      data_service = self.get_data_service()
      data_service.workspace
    rescue  Exception => e
      self.log_error(e, "Problem retrieving workspace")
    end
  end

  def workspace=(workspace)
    begin
      data_service = self.get_data_service()
      data_service.workspace = workspace
    rescue  Exception => e
      self.log_error(e, "Problem setting workspace")
    end
  end

  def workspaces
    begin
      data_service = self.get_data_service()
      data_service.workspaces
    rescue  Exception => e
      self.log_error(e, "Problem retrieving workspaces")
    end
  end

  def workspace_associations_counts()
    begin
      data_service = self.get_data_service()
      data_service.workspace_associations_counts()
    rescue  Exception => e
      self.log_error(e, "Problem retrieving workspace counts")
    end
  end

end