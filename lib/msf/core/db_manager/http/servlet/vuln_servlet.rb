module VulnServlet

  def self.api_path
    '/api/1/msf/vuln'
  end

  def self.registered(app)
    app.post VulnServlet.api_path, &report_vuln
  end

  #######
  private
  #######

  def self.report_vuln
    lambda {
      job = lambda { |opts|
        get_db().report_vuln(opts)
      }
      exec_report_job(request, &job)
    }
  end

end