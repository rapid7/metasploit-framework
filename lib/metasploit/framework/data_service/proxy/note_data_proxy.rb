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

  def find_or_create_note(opts)
    begin
      note = notes(opts.clone)
      if note.nil? || note.first.nil?
        note = report_note(opts.clone)
      else
        note = note.first
      end
      note
    rescue => e
      self.log_error(e, "Problem finding or creating note")
    end
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