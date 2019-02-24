module DbImportDataProxy
  def import(opts, &block)
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.import(opts, &block)
    rescue Exception => e
      self.log_error(e, "Problem generating DB Export")
    end
  end

  def import_file(opts, &block)
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.import_file(opts, &block)
    rescue Exception => e
      self.log_error(e, "Problem generating DB Export")
    end
  end
end
