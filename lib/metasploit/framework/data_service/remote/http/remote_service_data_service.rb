module RemoteServiceDataService
  SERVICE_API_PATH  = '/api/v1/services'
  SERVICE_MDM_CLASS = 'Mdm::Service'

  def services(opts)
    json_to_mdm_object(self.get_data(SERVICE_API_PATH, nil, opts), SERVICE_MDM_CLASS, [])
  end

  def report_service(opts)
    json_to_mdm_object(self.post_data(SERVICE_API_PATH, opts), SERVICE_MDM_CLASS).first
  end

  def delete_service(opts)
    json_to_mdm_object(self.delete_data(SERVICE_API_PATH, opts), SERVICE_MDM_CLASS)
  end
end
