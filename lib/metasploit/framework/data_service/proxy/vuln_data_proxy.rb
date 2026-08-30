
module VulnDataProxy

  def vulns(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.vulns(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving vulns")
    end
  end

  def find_or_create_vuln(opts)
    begin
      vuln = vulns(opts.clone)
      if vuln.nil? || vuln.first.nil?
        vuln = report_vuln(opts.clone)
      else
        vuln = vuln.first
      end
      vuln
    rescue => e
      self.log_error(e, "Problem finding or creating vuln")
    end
  end

  def report_vuln(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_vuln(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting vuln")
    end
  end

  def update_vuln(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_vuln(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating vuln")
    end
  end

  def delete_vuln(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.delete_vuln(opts)
      end
    rescue => e
      self.log_error(e, "Problem deleting vuln")
    end
  end
end