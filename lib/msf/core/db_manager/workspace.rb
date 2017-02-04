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
end
