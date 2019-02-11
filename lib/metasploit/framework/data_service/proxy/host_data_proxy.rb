module HostDataProxy

  def hosts(opts = {})
    begin
      self.data_service_operation do |data_service|
        opts[:non_dead] = false unless opts.has_key?(:non_dead)
        opts[:address] = opts.delete(:address) || opts.delete(:host)
        opts[:search_term] = nil unless opts.has_key?(:search_term)
        add_opts_workspace(opts)
        data_service.hosts(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving hosts")
    end
  end

  def find_or_create_host(opts)
    begin
      host = hosts(opts.clone)
      if host.nil? || host.first.nil?
        host = report_host(opts.clone)
      else
        host = host.first
      end
      host
    rescue => e
      self.log_error(e, "Problem finding or creating host")
    end
  end

  def get_host(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.get_host(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving host")
    end
  end

  def report_host(opts)
    return unless valid(opts)

    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_host(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting host")
    end
  end

  def update_host(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_host(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating host")
    end
  end

  def delete_host(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.delete_host(opts)
      end
    rescue => e
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
