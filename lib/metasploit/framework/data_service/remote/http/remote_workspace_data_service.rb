require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteWorkspaceDataService
  include ResponseDataHelper

  WORKSPACE_API_PATH = '/api/1/msf/workspace'
  DEFAULT_WORKSPACE_NAME = 'default'

  def find_workspace(workspace_name)
    workspace = workspace_cache[workspace_name]
    return workspace unless (workspace.nil?)

    workspace = json_to_open_struct_object(self.get_data({:workspace_name => workspace_name}, WORKSPACE_API_PATH))
    workspace_cache[workspace_name] = workspace
  end

  def add_workspace(workspace_name)
    self.post_data({:workspace_name => workspace_name}, WORKSPACE_API_PATH)
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
    json_to_open_struct_object(self.get_data({:all => true}, WORKSPACE_API_PATH), [])
  end

  protected

  def workspace_cache
    @workspace_cache ||= {}
  end

  def current_workspace_name
    @current_workspace_name ||= DEFAULT_WORKSPACE_NAME
  end
end