module EventDataProxy

  def report_event(opts)
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.report_event(opts)
    rescue => e
      self.log_error(e, "Problem reporting event")
    end
  end

end