module NoteDataProxy
  def report_note(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_note(opts)
    rescue  Exception => e
      elog "Problem reporting note: #{e.message}"
    end
  end
end