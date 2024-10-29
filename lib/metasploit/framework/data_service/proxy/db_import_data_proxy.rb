module DbImportDataProxy
  def import(opts, &block)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.import(opts, &block)
      end
    rescue Exception => e
      self.log_error(e, "Problem generating DB Import")
    end
  end

  def import_file(opts, &block)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.import_file(opts, &block)
      end
    rescue Exception => e
      self.log_error(e, "Problem generating DB Import")
    end
  end
end
