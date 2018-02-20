module ServiceServlet

  def self.api_path
    '/api/v1/services'
  end

  def self.registered(app)
    app.get  ServiceServlet.api_path, &get_services
    app.post ServiceServlet.api_path, &report_service
  end

  #######
  private
  #######

  def self.get_services
    lambda {
      begin
        opts = params.symbolize_keys
        data = get_db().services(opts[:workspace],
                                 opts[:only_up],
                                 opts[:proto],
                                 opts[:address],
                                 opts[:ports],
                                 opts[:names])
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
