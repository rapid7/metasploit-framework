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

  def report_web_page(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.report_web_page(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting web page")
    end
  end

  def report_web_form(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.report_web_form(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting web form")
    end
  end

  def report_web_vuln(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.report_web_vuln(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting web vuln")
    end
  end
end