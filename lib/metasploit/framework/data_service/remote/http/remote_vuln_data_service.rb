module RemoteVulnDataService

  VULN_API_PATH = '/api/v1/vulns'
  def report_vuln(opts)
    self.post_data_async(VULN_API_PATH, opts)
  end
end