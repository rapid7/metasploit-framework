module SessionEventDataProxy

  def report_session_event(opts)
    begin
      data_service = self.get_data_service()
      # The full Session object contains in-memory instances of data we do not need to store.
      opts[:session] = opts[:session].sid
      data_service.report_session_event(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_session_event threw exception: #{e.message}"
    end
  end
end