module WorkspaceDataProxy

  def find_workspace(workspace_name)
    begin
      data_service = self.get_data_service()
      data_service.find_workspace(workspace_name)
    rescue  Exception => e
      elog "Problem finding workspace: #{e.message}"
    end
  end

  def add_workspace(workspace_name)
    begin
      data_service = self.get_data_service()
      data_service.add_workspace(workspace_name)
    rescue  Exception => e
      elog "Problem adding workspace: #{e.message}"
    end
  end

  def default_workspace
    begin
      data_service = self.get_data_service()
      data_service.default_workspace
    rescue  Exception => e
      elog "Problem getting the default workspace: #{e.message}"
    end
  end

  def workspace
    begin
      data_service = self.get_data_service()
      data_service.workspace
    rescue  Exception => e
      elog "Problem retrieving workspace: #{e.message}"
    end
  end

  def workspace=(workspace)
    begin
      data_service = self.get_data_service()
      data_service.workspace = workspace
    rescue  Exception => e
      elog "Problem setting workspace: #{e.message}"
    end
  end

  def workspaces
    begin
      data_service = self.get_data_service()
      data_service.workspaces
    rescue  Exception => e
      elog "Problem retrieving workspaces: #{e.message}"
    end
  end

  def workspace_associations_counts()
    begin
      data_service = self.get_data_service()
      data_service.workspace_associations_counts()
    rescue  Exception => e
      elog "Problem retrieving workspaces counts: #{e.message}"
    end
  end

end