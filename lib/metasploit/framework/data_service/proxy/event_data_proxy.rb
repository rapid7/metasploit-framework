module EventDataProxy

  def report_event(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_event(opts)
    rescue  Exception => e
      self.log_error(e, "Problem reporting event")
    end
  end

end