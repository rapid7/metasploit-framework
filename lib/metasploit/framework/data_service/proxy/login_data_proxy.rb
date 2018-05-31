module LoginDataProxy
  def logins(opts = {})
    begin
      data_service = self.get_data_service
      data_service.logins(opts)
    rescue => e
      self.log_error(e, "Problem retrieving logins")
    end
  end

  def create_credential_login(opts)
    begin
      data_service = self.get_data_service
      data_service.create_credential_login(opts)
    rescue => e
      self.log_error(e, "Problem creating logins")
    end
  end
end