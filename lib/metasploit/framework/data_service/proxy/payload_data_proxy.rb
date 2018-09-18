module PayloadDataProxy

  def payloads(opts)
    begin
      data_service = self.get_data_service
      data_service.payloads(opts)
    rescue => e
      self.log_error(e, "Problem retrieving payload")
    end
  end

  def create_payload(opts)
    begin
      data_service = self.get_data_service
      data_service.create_payload(opts)
    rescue => e
      self.log_error(e, "Problem creating payload")
    end
  end

  def update_payload(opts)
    begin
      data_service = self.get_data_service
      data_service.update_payload(opts)
    rescue => e
      self.log_error(e, "Problem updating payload")
    end
  end

  def delete_payload(opts)
    begin
      data_service = self.get_data_service
      data_service.delete_payload(opts)
    rescue => e
      self.log_error(e, "Problem deleting payload")
    end
  end

end
