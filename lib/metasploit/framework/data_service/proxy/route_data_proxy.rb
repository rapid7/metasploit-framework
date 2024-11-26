module RouteDataProxy
  def report_session_route(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_session_route(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting route")
    end
  end

  def report_session_route_remove(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_session_route_remove(opts)
      end
    rescue => e
      self.log_error(e, "Problem removing route")
    end
  end

end
