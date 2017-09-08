require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteWorkspaceDataService
  include ResponseDataHelper

  WORKSPACE_COUNTS_API_PATH = '/api/1/msf/workspace/counts'
  WORKSPACE_API_PATH = '/api/1/msf/workspace'
  DEFAULT_WORKSPACE_NAME = 'default'

  def find_workspace(workspace_name)
    workspace = workspace_cache[workspace_name]
    return workspace unless (workspace.nil?)

    workspace = json_to_open_struct_object(self.get_data(WORKSPACE_API_PATH, {:workspace_name => workspace_name}))
    workspace_cache[workspace_name] = workspace
  end

  def add_workspace(workspace_name)
    response = self.post_data(WORKSPACE_API_PATH, {:workspace_name => workspace_name})
    json_to_open_struct_object(response, nil)
  end

  def default_workspace
    find_workspace(DEFAULT_WORKSPACE_NAME)
  end

  def workspace
    find_workspace(current_workspace_name)
  end

  def workspace=(workspace)
    @current_workspace_name = workspace.name
  end

  def workspaces
    json_to_open_struct_object(self.get_data(WORKSPACE_API_PATH, {:all => true}), [])
  end

  def workspace_associations_counts()
    json_to_open_struct_object(self.get_data(WORKSPACE_COUNTS_API_PATH), [])
  end

  #########
  protected
  #########

  def workspace_cache
    @workspace_cache ||= {}
  end

  def current_workspace_name
    @current_workspace_name ||= DEFAULT_WORKSPACE_NAME
  end

end