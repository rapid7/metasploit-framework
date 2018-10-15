module RemoteEventDataService
  EVENT_API_PATH = '/api/v1/events'

  def report_event(opts)
    self.post_data_async(EVENT_API_PATH, opts)
  end
end