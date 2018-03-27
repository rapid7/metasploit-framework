module VulnAttemptServlet

  def self.api_path
    '/api/v1/vuln-attempts'
  end

  def self.api_path_with_id
    "#{VulnAttemptServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get VulnAttemptServlet.api_path_with_id, &get_vuln_attempt
    app.post VulnAttemptServlet.api_path, &report_vuln_attempt
  end

  #######
  private
  #######

  def self.get_vuln_attempt
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db.vuln_attempts(params.symbolize_keys)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_vuln_attempt
    lambda {
      begin
        job = lambda { |opts|
          vuln_id = opts.delete(:vuln_id)
          vuln = get_db.vulns(id: vuln_id).first
          get_db.report_vuln_attempt(vuln, opts)
        }
        exec_report_job(request, &job)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end
end