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
    puts "default_workspace is being called directly from dbmanager"
    caller.each { |line| puts "#{line}\n"}
  # ::ActiveRecord::Base.connection_pool.with_connection {
  #   ::Mdm::Workspace.default
  # }
  end

  def find_workspace(name)
    puts "find_workspace is being called directly from dbmanager"
    caller.each { |line| puts "#{line}\n"}
  # ::ActiveRecord::Base.connection_pool.with_connection {
  #   ::Mdm::Workspace.find_by_name(name)
  # }
  end

  def workspace
    puts "workspace is being called directly from dbmanager"
    caller.each { |line| puts "#{line}\n"}
  # ::ActiveRecord::Base.connection_pool.with_connection {
  #   ::Mdm::Workspace.find(@workspace_id)
  # }
  end

  def workspace=(workspace)
    #@workspace_id = workspace.id
    puts "workspace= is being called directly from dbmanager"
    caller.each { |line| puts "#{line}\n"}
  end

  def workspaces(opts = {})
  ::ActiveRecord::Base.connection_pool.with_connection {
    search_term = opts.delete(:search_term)

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
