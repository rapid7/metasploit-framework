module WorkspaceDataProxy

  def find_workspace(workspace_name)
    begin
      data_service = self.get_data_service()
      data_service.find_workspace(workspace_name)
    rescue  Exception => e
      puts"Call to  #{data_service.class}#find_workspace threw exception: #{e.message}"
    end
  end

  def add_workspace(workspace_name)
    begin
      data_service = self.get_data_service()
      data_service.add_workspace(workspace_name)
    rescue  Exception => e
      puts"Call to  #{data_service.class}#add_workspace threw exception: #{e.message}"
    end
  end

  def default_workspace
    begin
      data_service = self.get_data_service()
      data_service.default_workspace
    rescue  Exception => e
      puts"Call to  #{data_service.class}#default_workspace threw exception: #{e.message}"
    end
  end

  def workspace
    begin
      data_service = self.get_data_service()
      data_service.workspace
    rescue  Exception => e
      puts"Call to  #{data_service.class}#workspace threw exception: #{e.message}"
    end
  end

  def workspace=(workspace)
    begin
      data_service = self.get_data_service()
      data_service.workspace = workspace
    rescue  Exception => e
      puts"Call to  #{data_service.class}#find_workspace threw exception: #{e.message}"
    end
  end

  def workspaces
    begin
      data_service = self.get_data_service()
      data_service.workspaces
    rescue  Exception => e
      puts"Call to  #{data_service.class}#workspaces threw exception: #{e.message}"
    end
  end

  def workspace_associations_counts()
    begin
      data_service = self.get_data_service()
      data_service.workspace_associations_counts()
    rescue  Exception => e
      puts"Call to  #{data_service.class}#workspace_associations_counts threw exception: #{e.message}"
    end
  end

end