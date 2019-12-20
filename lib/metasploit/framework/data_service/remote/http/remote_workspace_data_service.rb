require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteWorkspaceDataService
  include ResponseDataHelper

  WORKSPACE_API_PATH = '/api/v1/workspaces'
  WORKSPACE_MDM_CLASS = 'Mdm::Workspace'

  def add_workspace(opts)
    response = self.post_data(WORKSPACE_API_PATH, opts)
    json_to_mdm_object(response, WORKSPACE_MDM_CLASS).first
  end

  def default_workspace
    json_to_mdm_object(self.get_data(WORKSPACE_API_PATH, nil, { name: Msf::DBManager::Workspace::DEFAULT_WORKSPACE_NAME }), WORKSPACE_MDM_CLASS)
  end

  def workspace
    # The @current_workspace is tracked on the client side, so attempting to call it directly from the RemoteDataService
    # will not return the correct results. Run it back through the proxy.
    wlog "[DEPRECATION] Calling workspace from within the RemoteDataService is no longer supported. Please call from WorkspaceDataProxy instead."
    caller.each { |line| wlog "#{line}"}
  end

  def workspace=(workspace)
    # The @current_workspace is tracked on the client side, so attempting to call it directly from the RemoteDataService
    # will not return the correct results. Run it back through the proxy.
    wlog "[DEPRECATION] Setting the current workspace from the RemoteDataService is no longer supported. Please call from WorkspaceDataProxy instead."
    caller.each { |line| wlog "#{line}"}
  end

  def workspaces(opts)
    path = get_path_select(opts, WORKSPACE_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), WORKSPACE_MDM_CLASS)
  end

  def delete_workspaces(opts)
    json_to_mdm_object(self.delete_data(WORKSPACE_API_PATH, opts), WORKSPACE_MDM_CLASS)
  end

  def update_workspace(opts)
    path = WORKSPACE_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{WORKSPACE_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), WORKSPACE_MDM_CLASS).first
  end

end
