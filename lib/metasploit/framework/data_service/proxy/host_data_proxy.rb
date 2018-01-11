module HostDataProxy

  def hosts(wspace = workspace, non_dead = false, addresses = nil)
    begin
      data_service = self.get_data_service()
      opts = {}
      opts[:wspace] = wspace
      opts[:non_dead] = non_dead
      opts[:addresses] = addresses
      data_service.hosts(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#hosts threw exception: #{e.message}"
    end
  end

  # TODO: Shouldn't this proxy to RemoteHostDataService#find_or_create_host ?
  # It's currently skipping the "find" part
  def find_or_create_host(opts)
    puts 'Calling find host'
    report_host(opts)
  end

  def report_host(opts)
    return unless valid(opts)

    begin
      data_service = self.get_data_service()
      data_service.report_host(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_host threw exception: #{e.message}"
      opts.each { |k, v| puts "#{k} : #{v}" }
    end
  end

  def report_hosts(hosts)
    begin
      data_service = self.get_data_service()
      data_service.report_hosts(hosts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_hosts threw exception: #{e.message}"
    end
  end

  def delete_host(opts)
    begin
      data_service = self.get_data_service()
      data_service.delete_host(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#delete_host threw exception: #{e.message}"
    end
  end

  private

  def valid(opts)
    unless opts[:host]
      puts 'Invalid host hash passed, :host is missing'
      return false
    end

    # Sometimes a host setup through a pivot will see the address as "Remote Pipe"
    if opts[:host].eql? "Remote Pipe"
      puts "Invalid host hash passed, address was of type 'Remote Pipe'"
      return false
    end

    return true
  end

end
