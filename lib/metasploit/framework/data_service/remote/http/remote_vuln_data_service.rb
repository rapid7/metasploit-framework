module RemoteVulnDataService

  VULN_API_PATH = '/api/1/msf/vuln'
  def report_vuln(opts)
    self.post_data_async(VULN_API_PATH, opts)
  end
end