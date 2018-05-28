module ServiceServlet

  def self.api_path
    '/api/v1/services'
  end

  def self.api_path_with_id
    "#{ServiceServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get  ServiceServlet.api_path, &get_services
    app.post ServiceServlet.api_path, &report_service
    app.put ServiceServlet.api_path_with_id, &update_service
    app.delete ServiceServlet.api_path, &delete_service
  end

  #######
  private
  #######

  def self.get_services
    lambda {
      begin
        opts = sanitize_params(params)
        data = get_db.services(opts)
        includes = [:host]
        set_json_response(data, includes)
      rescue => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_service
    lambda {
      job = lambda { |opts| get_db.report_service(opts) }
      includes = [:host]
      exec_report_job(request, includes, &job)
    }
  end

  def self.update_service
    lambda {
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_service(opts)
        set_json_response(data)
      rescue => e
        set_error_on_response(e)
      end
    }
  end

  def self.delete_service
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_service(opts)
        set_json_response(data)
      rescue => e
        set_error_on_response(e)
      end
    }
  end
end
