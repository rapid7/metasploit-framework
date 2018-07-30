require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteSessionEventDataService
  include ResponseDataHelper

  SESSION_EVENT_API_PATH = '/api/v1/session-events'
  SESSION_EVENT_MDM_CLASS = 'Mdm::SessionEvent'

  def session_events(opts = {})
    json_to_mdm_object(self.get_data(SESSION_EVENT_API_PATH, opts), SESSION_EVENT_MDM_CLASS, [])
  end

  def report_session_event(opts)
    opts[:session] = opts[:session].db_record
    self.post_data_async(SESSION_EVENT_API_PATH, opts)
  end
end