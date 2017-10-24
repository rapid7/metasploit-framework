require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteSessionEventDataService
  include ResponseDataHelper

  SESSION_EVENT_PATH = '/api/1/msf/session_event'

  def session_events(opts = {})
    json_to_open_struct_object(self.get_data(SESSION_EVENT_PATH, opts), [])
  end

  def report_session_event(opts)
    opts[:session] = opts[:session].db_record
    self.post_data_async(SESSION_EVENT_PATH, opts)
  end
end