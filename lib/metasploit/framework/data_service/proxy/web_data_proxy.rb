module WebDataProxy
  def report_web_site(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_web_site(opts)
    rescue  Exception => e
      elog "Problem reporting web site: #{e.message}"
    end
  end
end