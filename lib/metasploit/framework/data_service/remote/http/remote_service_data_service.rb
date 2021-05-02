module RemoteServiceDataService
  SERVICE_API_PATH  = '/api/v1/services'
  SERVICE_MDM_CLASS = 'Mdm::Service'

  def services(opts)
    path = get_path_select(opts, SERVICE_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), SERVICE_MDM_CLASS)
  end

  def report_service(opts)
    json_to_mdm_object(self.post_data(SERVICE_API_PATH, opts), SERVICE_MDM_CLASS).first
  end

  def update_service(opts)
    path = SERVICE_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{SERVICE_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), SERVICE_MDM_CLASS)
  end

  def delete_service(opts)
    json_to_mdm_object(self.delete_data(SERVICE_API_PATH, opts), SERVICE_MDM_CLASS)
  end
end
