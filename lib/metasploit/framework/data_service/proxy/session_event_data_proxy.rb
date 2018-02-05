module SessionEventDataProxy

  # def session_events
  #   begin
  #     data_service = self.get_data_service()
  #   rescue  Exception => e
  #     elog "Problem retrieving session events: #{e.message}"
  #   end
  # end

  def report_session_event(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_session_event(opts)
    rescue Exception => e
      elog "Problem reporting session event: #{e.message}"
    end
  end
end