require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteRouteDataService
  include ResponseDataHelper

  ROUTE_API_PATH = '/api/v1/routes'
  ROUTE_MDM_CLASS = 'Mdm::Route'

  def report_session_route(opts)
    json_to_mdm_object(self.post_data(ROUTE_API_PATH, opts), ROUTE_MDM_CLASS).first
  end

  def report_session_route_remove(opts)
    path = get_path_select(opts, ROUTE_API_PATH) + '/remove'
    json_to_mdm_object(self.post_data(path, opts), ROUTE_MDM_CLASS).first
  end

end
