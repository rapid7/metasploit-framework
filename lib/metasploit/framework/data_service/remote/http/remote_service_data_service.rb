module RemoteServiceDataService
  SERVICE_API_PATH = '/api/v1/services'

  def report_service(opts)
    self.post_data_async(SERVICE_API_PATH, opts)
  end
end