require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteWorkspaceDataService
  include ResponseDataHelper

  # TODO: should counts be a flag in query data for the workspaces resource?
  WORKSPACE_COUNTS_API_PATH = '/api/v1/workspaces/counts'
  WORKSPACE_API_PATH = '/api/v1/workspaces'
  WORKSPACE_MDM_CLASS = 'Mdm::Workspace'
  DEFAULT_WORKSPACE_NAME = 'default'

  def find_workspace(workspace_name)
    workspace = workspace_cache[workspace_name]
    return workspace unless (workspace.nil?)

    workspace = json_to_mdm_object(self.get_data(WORKSPACE_API_PATH, {:workspace_name => workspace_name}), WORKSPACE_MDM_CLASS).first
    workspace_cache[workspace_name] = workspace
  end

  def add_workspace(workspace_name)
    response = self.post_data(WORKSPACE_API_PATH, {:workspace_name => workspace_name})
    json_to_mdm_object(response, WORKSPACE_MDM_CLASS, nil)
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
    json_to_mdm_object(self.get_data(WORKSPACE_API_PATH, {:all => true}), WORKSPACE_MDM_CLASS, [])
  end

  def workspace_associations_counts()
    json_to_mdm_object(self.get_data(WORKSPACE_COUNTS_API_PATH, []), WORKSPACE_MDM_CLASS, [])
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