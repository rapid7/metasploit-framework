module PayloadServlet

  def self.api_path
    '/api/v1/payloads'
  end

  def self.api_path_with_id
    "#{PayloadServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get PayloadServlet.api_path_with_id, &get_payload
    app.post PayloadServlet.api_path, &create_payload
    app.put PayloadServlet.api_path_with_id, &update_payload
    app.delete PayloadServlet.api_path, &delete_payload
  end

  #######
  private
  #######

  def self.create_payload
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.create_payload(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the payload:', code: 500)
      end
    }
  end

  def self.get_payload
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.payloads(sanitized_params)
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error getting the payload:', code: 500)
      end
    }
  end

  def self.update_payload
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_payload(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the payload:', code: 500)
      end
    }
  end

  def self.delete_payload
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_payload(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the payload:', code: 500)
      end
    }
  end

end
