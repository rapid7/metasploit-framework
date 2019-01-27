module WebDataProxy
  def report_web_site(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.report_web_site(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting website")
    end
  end
end