module EventDataProxy

  def report_event(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_event(opts)
    rescue  Exception => e
      elog "Call to  #{data_service.class}#report_event threw exception: #{e.message}"
    end
  end

end