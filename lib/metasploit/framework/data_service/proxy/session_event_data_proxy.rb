module SessionEventDataProxy

  def report_session_event(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_session_event(opts)
    rescue => e
      self.log_error(e, "Problem reporting session event")
    end
  end
end