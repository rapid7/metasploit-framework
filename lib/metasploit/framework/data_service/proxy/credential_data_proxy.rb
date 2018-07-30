module CredentialDataProxy

  def create_credential(opts)
    begin
      data_service = self.get_data_service()
      data_service.create_credential(opts)
    rescue Exception => e
      self.log_error(e, "Problem creating credential")
    end
  end

  def creds(opts = {})
    begin
      data_service = self.get_data_service
      data_service.creds(opts)
    rescue Exception => e
      self.log_error(e, "Problem retrieving credentials")
    end
  end
end