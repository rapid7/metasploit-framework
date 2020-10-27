module WebServlet

  def self.api_path
    '/api/v1/webs'
  end

  def self.registered(app)
    app.post WebServlet.api_path, &report_web
    app.post "#{WebServlet.api_path}/page", &report_web_page
    app.post "#{WebServlet.api_path}/form", &report_web_form
    app.post "#{WebServlet.api_path}/vuln", &report_web_vuln

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

  def self.report_web_page
    lambda {
      warden.authenticate!
      job = lambda { |opts|  get_db().report_web_page(opts) }
      exec_report_job(request, &job)
    }
  end

  def self.report_web_form
    lambda {
      warden.authenticate!
      job = lambda { |opts|  get_db().report_web_form(opts) }
      exec_report_job(request, &job)
    }
  end

  def self.report_web_vuln
    lambda {
      warden.authenticate!
      job = lambda { |opts|  get_db().report_web_vuln(opts) }
      exec_report_job(request, &job)
    }
  end

end