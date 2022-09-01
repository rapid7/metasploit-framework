module PayloadDataProxy

  def payloads(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.payloads(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving payload")
    end
  end

  def create_payload(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.create_payload(opts)
      end
    rescue => e
      self.log_error(e, "Problem creating payload")
    end
  end

  def update_payload(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_payload(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating payload")
    end
  end

  def delete_payload(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.delete_payload(opts)
      end
    rescue => e
      self.log_error(e, "Problem deleting payload")
    end
  end

end
