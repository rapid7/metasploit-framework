module SessionDataProxy
  def report_session(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_session(opts)
    rescue  Exception => e
      self.log_error(e, "Problem reporting session")
    end
  end
end




