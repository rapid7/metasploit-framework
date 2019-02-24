module DbExportDataProxy
  def run_db_export(path, format)
    begin
      data_service = self.get_data_service
      opts = {
          path: path,
          format: format
      }
      add_opts_workspace(opts)
      data_service.run_db_export(opts)
    rescue => e
      self.log_error(e, "Problem generating DB Export")
    end
  end
end
