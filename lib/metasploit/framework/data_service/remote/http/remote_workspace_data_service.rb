require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteWorkspaceDataService
  include ResponseDataHelper

  WORKSPACE_API_PATH = '/api/v1/workspaces'
  WORKSPACE_MDM_CLASS = 'Mdm::Workspace'
  DEFAULT_WORKSPACE_NAME = 'default'

  def add_workspace(workspace_name)
    response = self.post_data(WORKSPACE_API_PATH, {:workspace_name => workspace_name})
    json_to_mdm_object(response, WORKSPACE_MDM_CLASS, nil).first
  end

  def default_workspace
    json_to_mdm_object(self.get_data(WORKSPACE_API_PATH, nil, {:name => default}), WORKSPACE_MDM_CLASS, [])
  end

  def workspace
    find_workspace(current_workspace_name)
  end

  def workspace=(workspace)
    @current_workspace_name = workspace.name
  end

  def workspaces(opts)
    json_to_mdm_object(self.get_data(WORKSPACE_API_PATH, nil, opts), WORKSPACE_MDM_CLASS, [])
  end

  def delete_workspaces(opts)
    json_to_mdm_object(self.delete_data(WORKSPACE_API_PATH, opts), WORKSPACE_MDM_CLASS, [])
  end

  def update_workspace(opts)
    path = WORKSPACE_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{WORKSPACE_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), WORKSPACE_MDM_CLASS, [])
  end

end
