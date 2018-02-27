module ServiceDataProxy

  def report_service(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_service(opts)
    rescue  Exception => e
      self.log_error(e, "Problem reporting service")
    end
  end

  def services(wspace = workspace, only_up = false, proto = nil, addresses = nil, ports = nil, names = nil)
    begin
      data_service = self.get_data_service()
      opts = {}
      opts[:workspace] = wspace
      opts[:only_up] = only_up
      opts[:proto] = proto
      opts[:address] = addresses
      opts[:ports] = ports
      opts[:names] = names
      data_service.services(opts)
    rescue Exception => e
      elog "Problem retrieving services: #{e.message}"
    end
  end
end
