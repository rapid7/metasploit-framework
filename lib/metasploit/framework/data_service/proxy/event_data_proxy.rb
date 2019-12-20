module EventDataProxy

  def events(opts = {})
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.events(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving events")
    end
  end

  def report_event(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_event(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting event")
    end
  end

end