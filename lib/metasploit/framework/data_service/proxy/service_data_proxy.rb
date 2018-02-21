module ServiceDataProxy

  def report_service(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_service(opts)
    rescue  Exception => e
      self.log_error(e, "Problem reporting service")
    end
  end

end