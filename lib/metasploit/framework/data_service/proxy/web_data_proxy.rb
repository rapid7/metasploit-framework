module WebDataProxy
  def report_web_site(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_web_site(opts)
    rescue => e
      self.log_error(e, "Problem reporting website")
    end
  end
end