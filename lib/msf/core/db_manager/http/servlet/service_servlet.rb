module ServiceServlet

  def self.api_path
    '/api/v1/services'
  end

  def self.registered(app)
    app.post ServiceServlet.api_path, &report_service
  end

  #######
  private
  #######

  def self.get_host
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().hosts(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_service
    lambda {
      job = lambda { |opts| get_db().report_service(opts) }
      exec_report_job(request, &job)
    }
  end
end