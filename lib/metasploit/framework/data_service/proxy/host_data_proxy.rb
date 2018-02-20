module HostDataProxy

  def hosts(wspace = workspace, non_dead = false, addresses = nil, search_term = nil)
    begin
      data_service = self.get_data_service()
      opts = {}
      opts[:wspace] = wspace
      opts[:non_dead] = non_dead
      opts[:address] = addresses
      opts[:search_term] = search_term
      data_service.hosts(opts)
    rescue Exception => e
      self.log_error(e, "Problem retrieving hosts")
    end
  end

  # TODO: Shouldn't this proxy to RemoteHostDataService#find_or_create_host ?
  # It's currently skipping the "find" part
  def find_or_create_host(opts)
    report_host(opts)
  end

  def report_host(opts)
    return unless valid(opts)

    begin
      data_service = self.get_data_service()
      data_service.report_host(opts)
    rescue Exception => e
      self.log_error(e, "Problem reporting host")
    end
  end

  def report_hosts(hosts)
    begin
      data_service = self.get_data_service()
      data_service.report_hosts(hosts)
    rescue Exception => e
      self.log_error(e, "Problem reporting hosts")
    end
  end

  def update_host(opts)
    begin
      data_service = self.get_data_service()
      data_service.update_host(opts)
    rescue Exception => e
      self.log_error(e, "Problem updating host")
    end
  end

  def delete_host(opts)
    begin
      data_service = self.get_data_service()
      data_service.delete_host(opts)
    rescue Exception => e
      self.log_error(e, "Problem deleting host")
    end
  end

  private

  def valid(opts)
    unless opts[:host]
      ilog 'Invalid host hash passed, :host is missing'
      return false
    end

    # Sometimes a host setup through a pivot will see the address as "Remote Pipe"
    if opts[:host].eql? "Remote Pipe"
      ilog "Invalid host hash passed, address was of type 'Remote Pipe'"
      return false
    end

    return true
  end

end
