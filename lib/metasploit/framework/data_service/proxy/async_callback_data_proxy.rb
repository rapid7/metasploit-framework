module AsyncCallbackDataProxy

  def async_callbacks(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.async_callbacks(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving async callback")
    end
  end

  def create_async_callback(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.create_async_callback(opts)
      end
    rescue => e
      self.log_error(e, "Problem creating async callback")
    end
  end

  def update_async_callback(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_async_callback(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating async callback")
    end
  end

  def delete_async_callback(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.delete_async_callback(opts)
      end
    rescue => e
      self.log_error(e, "Problem deleting async callback")
    end
  end

end

