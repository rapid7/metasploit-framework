module SessionEventDataProxy

  def session_events
    begin
      data_service = self.get_data_service()
      puts "In SessionEventDataProxy.session_events"
    rescue  Exception => e
      puts"Call to  #{data_service.class}#session_events threw exception: #{e.message}"
    end
  end

  def report_session_event(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_session_event(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_session_event threw exception: #{e.message}"
    end
  end
end