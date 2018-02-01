module ServiceDataProxy

  def report_service(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_service(opts)
    rescue  Exception => e
      elog "Call to  #{data_service.class}#report_service threw exception: #{e.message}"
    end
  end

end