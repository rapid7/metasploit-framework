module SessionDataProxy
  def report_session(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_session(opts)
    rescue  Exception => e
      elog "Problem reporting session: #{e.message}"
    end
  end
end




