module VulnAttemptDataProxy

  def vuln_attempts(opts)
    begin
      data_service = self.get_data_service()
      data_service.vuln_attempts(opts)
    rescue Exception => e
      self.log_error(e, "Problem retrieving vulnerability attempts")
    end
  end

  def report_vuln_attempt(vuln, opts)
    begin
      data_service = self.get_data_service()
      data_service.report_vuln_attempt(vuln, opts)
    rescue Exception => e
      self.log_error(e, "Problem reporting vulnerability attempts")
    end
  end
end