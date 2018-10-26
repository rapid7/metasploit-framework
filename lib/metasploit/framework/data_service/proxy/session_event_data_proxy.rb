module SessionEventDataProxy

  def report_session_event(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.report_session_event(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting session event")
    end
  end
end