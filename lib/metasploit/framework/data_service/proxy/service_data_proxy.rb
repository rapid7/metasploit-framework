module ServiceDataProxy

  def services(opts = {})
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.services(opts)
      end
    rescue => e
      self.log_error(e, 'Problem retrieving services')
    end
  end

  def find_or_create_service(opts)
    begin
      # create separate opts for find operation since the report operation uses slightly different keys
      # TODO: standardize option keys used for the find and report operations
      find_opts = opts.clone
      # convert host to nested hosts address
      find_opts[:hosts] = {address: find_opts.delete(:host)} if find_opts.key?(:host)

      service = services(find_opts)
      if service.nil? || service.first.nil?
        service = report_service(opts.clone)
      else
        service = service.first
      end
      service
    rescue => e
      self.log_error(e, "Problem finding or creating service")
    end
  end

  def report_service(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_service(opts)
      end
    rescue => e
      self.log_error(e, 'Problem reporting service')
    end
  end

  def update_service(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_service(opts)
      end
    rescue => e
      self.log_error(e, 'Problem updating service')
    end
  end

  def delete_service(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.delete_service(opts)
      end
    rescue => e
      self.log_error(e, 'Problem deleting service')
    end
  end
end
