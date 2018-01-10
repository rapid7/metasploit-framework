module SessionDataProxy
  def report_session(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_session(opts)
    rescue  Exception => e
      puts"Call to  #{data_service.class}#report_session threw exception: #{e.message}"
      puts e.backtrace.each { |line| puts "#{line}\n" }
    end
  end
end




