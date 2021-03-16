module Msf::WebServices::VulnAttemptServlet

  def self.api_path
    '/api/v1/vuln-attempts'
  end

  def self.api_path_with_id
    "#{self.api_path}/?:id?"
  end

  def self.registered(app)
    app.get self.api_path, &get_vuln_attempt
    app.get self.api_path_with_id, &get_vuln_attempt
    app.post self.api_path, &report_vuln_attempt
  end

  #######
  private
  #######

  def self.get_vuln_attempt
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.vuln_attempts(sanitized_params)
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving vuln attempts:', code: 500)
      end
    }
  end

  def self.report_vuln_attempt
    lambda {
      warden.authenticate!
      job = lambda { |opts|
        vuln_id = opts.delete(:vuln_id)
        wspace = opts.delete(:workspace)
        vuln = get_db.vulns(id: vuln_id).first
        get_db.report_vuln_attempt(vuln, opts)
      }
      exec_report_job(request, &job)
    }
  end
end
