module CredentialDataProxy

  def create_credential(opts)
    begin
      data_service = self.get_data_service()
      data_service.create_credential(opts)
    rescue Exception => e
      elog "Problem creating credential: #{e.message}"
    end
  end

  def creds(opts = {})
    begin
      data_service = self.get_data_service
      data_service.creds(opts)
    rescue Exception => e
      elog "Problem retrieving credentials: #{e.message}"
    end
  end
end