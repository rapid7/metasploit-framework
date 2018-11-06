module SessionDataProxy
  def sessions(opts={})
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.sessions(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving sessions")
    end
  end

  def report_session(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_session(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting session")
    end
  end
end




