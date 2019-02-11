require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteEventDataService
  include ResponseDataHelper

  EVENT_API_PATH = '/api/v1/events'
  EVENT_MDM_CLASS = 'Mdm::Event'

  def events(opts)
    path = get_path_select(opts, EVENT_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), EVENT_MDM_CLASS, [])
  end

  def report_event(opts)
    self.post_data_async(EVENT_API_PATH, opts)
  end
end