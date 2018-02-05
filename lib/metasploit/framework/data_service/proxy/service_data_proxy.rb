module ServiceDataProxy

  def report_service(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_service(opts)
    rescue  Exception => e
      elog "Problem reporting service: #{e.message}"
    end
  end

end