module NoteDataProxy

  def notes(opts)
    begin
      data_service = self.get_data_service()
      data_service.notes(opts)
    rescue Exception => e
      self.log_error(e, "Problem retrieving notes")
    end
  end

  def report_note(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_note(opts)
    rescue  Exception => e
      self.log_error(e, "Problem reporting note")
    end
  end

  def update_note(opts)
    begin
      data_service = self.get_data_service()
      data_service.update_note(opts)
    rescue Exception => e
      self.log_error(e, "Problem updating note")
    end
  end

  def delete_note(opts)
    begin
      data_service = self.get_data_service()
      data_service.delete_note(opts)
    rescue Exception => e
      self.log_error(e, "Problem deleting note")
    end
  end
end