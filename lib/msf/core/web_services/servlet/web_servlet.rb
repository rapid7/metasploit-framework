module WebServlet

  def self.api_path
    '/api/v1/webs'
  end

  def self.registered(app)
    app.post WebServlet.api_path, &report_web
  end

  #######
  private
  #######

  def self.report_web
    lambda {
      warden.authenticate!
      job = lambda { |opts|  get_db().report_web_site(opts) }
      exec_report_job(request, &job)
    }
  end

end