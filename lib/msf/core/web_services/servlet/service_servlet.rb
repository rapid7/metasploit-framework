module Msf::WebServices::ServiceServlet

  def self.api_path
    '/api/v1/services'
  end

  def self.api_path_with_id
    "#{self.api_path}/?:id?"
  end

  def self.registered(app)
    app.get  self.api_path, &get_services
    app.get  self.api_path_with_id, &get_services
    app.post self.api_path, &report_service
    app.put self.api_path_with_id, &update_service
    app.delete self.api_path, &delete_service
  end

  #######
  private
  #######

  def self.get_services
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.services(sanitized_params)
        includes = [:host]
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data, includes: includes)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving services:', code: 500)
      end
    }
  end

  def self.report_service
    lambda {
      warden.authenticate!
      job = lambda { |opts| get_db.report_service(opts) }
      includes = [:host]
      exec_report_job(request, includes, &job)
    }
  end

  def self.update_service
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_service(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the service:', code: 500)
      end
    }
  end

  def self.delete_service
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_service(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the service:', code: 500)
      end
    }
  end
end
