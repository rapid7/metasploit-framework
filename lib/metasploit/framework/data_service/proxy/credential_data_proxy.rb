module CredentialDataProxy

  def create_credential(opts)
    begin
      data_service = self.get_data_service
      data_service.create_credential(opts)
    rescue => e
      self.log_error(e, "Problem creating credential")
    end
  end

  def creds(opts = {})
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.creds(opts)
    rescue => e
      self.log_error(e, "Problem retrieving credentials")
    end
  end
end