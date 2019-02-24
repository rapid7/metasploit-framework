module EventServlet

  def self.api_path
    '/api/v1/events'
  end

  def self.api_path_with_id
    "#{EventServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get EventServlet.api_path_with_id, &get_event
    app.post EventServlet.api_path, &report_event
  end

  #######
  private
  #######

  def self.get_event
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.events(sanitized_params)
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving events:', code: 500)
      end
    }
  end

  def self.report_event
    lambda {
      warden.authenticate!
      begin
        job = lambda { |opts| get_db.report_event(opts) }
        exec_report_job(request, &job)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the event:', code: 500)
      end
    }
  end
end