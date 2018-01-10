module WebDataProxy
  def report_web_site(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_web_site(opts)
    rescue  Exception => e
      puts"Call to  #{data_service.class}#report_web_site threw exception: #{e.message}"
    end
  end
end