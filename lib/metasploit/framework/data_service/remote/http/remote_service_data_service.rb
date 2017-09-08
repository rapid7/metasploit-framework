module RemoteServiceDataService
  SERVICE_API_PATH = '/api/1/msf/service'

  def report_service(opts)
    self.post_data_async(SERVICE_API_PATH, opts)
  end
end