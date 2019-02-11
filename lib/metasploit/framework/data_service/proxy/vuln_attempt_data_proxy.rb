module VulnAttemptDataProxy

  def vuln_attempts(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.vuln_attempts(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving vulnerability attempts")
    end
  end

  def report_vuln_attempt(vuln, opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_vuln_attempt(vuln, opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting vulnerability attempts")
    end
  end
end