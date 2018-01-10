module RemoteEventDataService
  EVENT_API_PATH = '/api/1/msf/event'

  def report_event(opts)
    self.post_data_async(EVENT_API_PATH, opts)
  end
end