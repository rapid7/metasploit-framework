module MsfDataProxy
  def get_msf_version
    begin
      self.data_service_operation do |data_service|
        data_service.get_msf_version
      end
    rescue => e
      self.log_error(e, "Problem retrieving Metasploit version")
    end
  end
end