module MsfDataProxy
  def get_msf_version
    begin
      data_service = self.get_data_service
      data_service.get_msf_version
    rescue Exception => e
      self.log_error(e, "Problem retrieving Metasploit version")
    end
  end
end