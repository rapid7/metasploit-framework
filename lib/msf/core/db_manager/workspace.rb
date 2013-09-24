module Msf::DBManager::Workspace
  def workspace=(workspace)
    @workspace_name = workspace.name
  end

  def workspace
    framework.db.find_workspace(@workspace_name)
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

  #
  # Creates a new workspace in the database
  #
  def add_workspace(name)
    ::ActiveRecord::Base.connection_pool.with_connection {
      ::Mdm::Workspace.find_or_create_by_name(name)
    }
  end

  def workspaces
    ::ActiveRecord::Base.connection_pool.with_connection {
      ::Mdm::Workspace.find(:all)
    }
  end
end