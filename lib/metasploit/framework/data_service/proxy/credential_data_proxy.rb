module CredentialDataProxy

  def create_credential(opts)
    begin
      data_service = self.get_data_service()
      data_service.create_credential(opts)
    rescue Exception => e
      elog "Call to #{data_service.class}#create_credential threw exception: #{e.message}"
    end
  end

  def creds(opts = {})
    begin
      data_service = self.get_data_service
      data_service.creds(opts)
    rescue Exception => e
      elog "Call to #{data_service.class}#credentials threw exception: #{e.message}"
    end
  end
end