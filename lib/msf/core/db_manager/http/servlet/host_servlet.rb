module HostServlet

  def self.api_path
    '/api/1/msf/host'
  end

  def self.registered(app)
    app.get HostServlet.api_path, &get_host
    app.post HostServlet.api_path, &report_host
  end

  #######
  private
  #######

  def self.get_host
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().hosts(opts)
        includes = [:loots]
        set_json_response(data, includes)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_host
    lambda {
        job = lambda { |opts| get_db().report_host(opts) }
        exec_report_job(request, &job)
    }
  end
end
