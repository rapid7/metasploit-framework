module ModuleDataProxy

  def modules(opts = {})
    begin
      data_service = self.get_data_service
      data_service.modules(opts)
    rescue => e
      self.log_error(e, "Problem retrieving modules")
    end
  end


end