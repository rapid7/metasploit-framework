module SessionServlet

  def self.api_path
    '/api/v1/sessions'
  end

  def self.api_path_with_id
    "#{SessionServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get SessionServlet.api_path_with_id, &get_session
    app.post SessionServlet.api_path, &report_session
  end

  #######
  private
  #######

  def self.get_session
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.sessions(sanitized_params)
        includes = [:host]
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data, includes: includes)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving sessions:', code: 500)
      end
    }
  end

  def self.report_session
    lambda {
      warden.authenticate!
      begin
        job = lambda { |opts|
          if opts[:session_data]
            get_db.report_session_dto(opts)
          else
            get_db.report_session_host_dto(opts)
          end
        }
        exec_report_job(request, &job)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the session:', code: 500)
      end
    }
  end

end
