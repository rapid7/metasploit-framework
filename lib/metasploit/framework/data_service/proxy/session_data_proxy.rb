module SessionDataProxy
  def sessions(opts={})
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.sessions(opts)
    rescue => e
      self.log_error(e, "Problem retrieving sessions")
    end
  end

  def report_session(opts)
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.report_session(opts)
    rescue => e
      self.log_error(e, "Problem reporting session")
    end
  end
end




