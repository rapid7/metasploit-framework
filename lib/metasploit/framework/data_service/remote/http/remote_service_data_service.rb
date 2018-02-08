module RemoteServiceDataService
  SERVICE_API_PATH  = '/api/v1/services'
  SERVICE_MDM_CLASS = 'Mdm::Service'

  def report_service(opts)
    self.post_data_async(SERVICE_API_PATH, opts)
  end

  def services(opts)
    json_to_mdm_object(self.get_data(SERVICE_API_PATH, nil, opts), SERVICE_MDM_CLASS, [])
  end
end
