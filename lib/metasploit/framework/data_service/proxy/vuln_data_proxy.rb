module VulnDataProxy

  def report_vuln(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_vuln(opts)
    rescue  Exception => e
      elog "Problem reporting vulnerability: #{e.message}"
    end
  end

end