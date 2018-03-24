module NoteDataProxy
  def report_note(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_note(opts)
    rescue  Exception => e
      self.log_error(e, "Problem reporting note")
    end
  end
end