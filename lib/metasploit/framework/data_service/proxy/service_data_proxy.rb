module ServiceDataProxy

  def services(wspace = workspace, opts = {})
    begin
      data_service = self.get_data_service()
      opts[:workspace] = wspace
      data_service.services(opts)
    rescue Exception => e
      self.log_error(e, 'Problem retrieving services')
    end
  end

  def find_or_create_service(opts)
    report_service(opts)
  end

  def report_service(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_service(opts)
    rescue  Exception => e
      self.log_error(e, 'Problem reporting service')
    end
  end

  def update_service(opts)
    begin
      data_service = self.get_data_service()
      data_service.update_service(opts)
    rescue Exception => e
      self.log_error(e, 'Problem updating service')
    end
  end

  def delete_service(opts)
    begin
      data_service = self.get_data_service()
      data_service.delete_service(opts)
    rescue Exception => e
      self.log_error(e, 'Problem deleting service')
    end
  end
end
