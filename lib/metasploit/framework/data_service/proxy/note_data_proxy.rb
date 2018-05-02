module NoteDataProxy

  def notes(opts)
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.notes(opts)
    rescue => e
      self.log_error(e, "Problem retrieving notes")
    end
  end

  # TODO: like other *DataProxy modules this currently skips the "find" part
  def find_or_create_note(opts)
    report_note(opts)
  end

  def report_note(opts)
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts)
      data_service.report_note(opts)
    rescue => e
      self.log_error(e, "Problem reporting note")
    end
  end

  def update_note(opts)
    begin
      data_service = self.get_data_service
      data_service.update_note(opts)
    rescue => e
      self.log_error(e, "Problem updating note")
    end
  end

  def delete_note(opts)
    begin
      data_service = self.get_data_service
      data_service.delete_note(opts)
    rescue => e
      self.log_error(e, "Problem deleting note")
    end
  end
end