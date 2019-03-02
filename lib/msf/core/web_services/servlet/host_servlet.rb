module HostServlet

  def self.api_path
    '/api/v1/hosts'
  end

  def self.api_path_with_id
    "#{HostServlet.api_path}/?:id?"
  end

  def self.api_search_path
    "#{HostServlet.api_path}/search"
  end

  def self.registered(app)
    app.get HostServlet.api_path_with_id, &get_host
    app.post HostServlet.api_path, &report_host
    app.put HostServlet.api_path_with_id, &update_host
    app.delete HostServlet.api_path, &delete_host
    app.post HostServlet.api_search_path, &search
  end

  #######
  private
  #######

  def self.get_host
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.hosts(sanitized_params)
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving hosts:', code: 500)
      end
    }
  end

  def self.report_host
    lambda {
      warden.authenticate!
      begin
        job = lambda { |opts|
          get_db.report_host(opts)
        }
        exec_report_job(request, &job)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the host:', code: 500)
      end
    }
  end

  def self.update_host
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_host(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the host:', code: 500)
      end
    }
  end

  def self.delete_host
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_host(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting hosts:', code: 500)
      end
    }
  end

  # TODO: remove once hosts and get_host method is merged
  def self.search
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.get_host(opts)
        set_json_data_response(response: data)
      rescue Exception => e
        print_error_and_create_response(error: e, message: 'There was an error searching for hosts:', code: 500)
      end
    }
  end

end
