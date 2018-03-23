module NoteServlet

  def self.api_path
    '/api/v1/notes'
  end

  def self.registered(app)
    app.post NoteServlet.api_path, &report_note
  end

  #######
  private
  #######

  def self.report_note
    lambda {
        job = lambda { |opts|  get_db().report_note(opts) }
        exec_report_job(request, &job)
    }
  end

end